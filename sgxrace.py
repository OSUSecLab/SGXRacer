#!/usr/bin/python3

import os
import sys
import angr
from angr import SimProcedure
from capstone import *
from capstone.x86_const import *
from capstone.x86 import *
import time
import copy
import filecmp
import argparse
import archinfo
import random
import subprocess
import gc
import datetime



class Info(object):
	def __init__(self):
		self.picflag = None
		self.project = None
		self.binaryfile = None
		self.asmfile = None
		self.hexdumpfile = None
		self.readelffile = None
		self.code = None
		self.args = None
		self.outputfile = None
		self.outputfile1 = None
		self.outputfile2 = None
		self.succssorsfile = None
		self.locksetfile = None
		self.gv_reverse_mapfile = None
		self.ots_once_caller_callee_mapfile = None

		# capstone insn list
		self.insns = []
		# instruction address to capstone insn map
		self.insnsmap = {}
		# list of instruction addresses
		self.insnaddrs = []

		# instruction address to objdump insn string line map
		self.insnlinesmap = {}

		self.codeoffset = None

		self.unsupportedlist = []
		self.xsavelist = []
		self.xsaveclist = []
		self.xsaveslist = []
		self.xsave64list = []
		self.xsavec64list = []
		self.xsaves64list = []
		self.fxsavelist = []
		self.fxsave64list = []
		self.xrstorlist = []
		self.xrstorslist = []
		self.xrstor64list = []
		self.xrstors64list = []
		self.fxrstorlist = []
		self.fxrstor64list = []

		self.repstoslist = []
		self.repmovsqlist = []

		self.rdrandlist = []

		self.wrfsbaselist = []

		self.enclulist = []
		self.enclaveentry = None
		self.abortfunction = None

		self.state = None
		self.emptystate = None
		self.states = []
		self.targets1 = []
		self.targets2 = []
		self.succs = []

		self.encluflag = 0

		self.g = []
		self.interestedregs = ["rax","rbx","rcx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15"]
		self.controllableregs = ["rbx","rdx","rdi","rsi","r8","r9","r10","r11","r12","r13","r14","r15"]
		self.firstocallmet = 0
		self.tstart = 0
		self.tend = 0

		self.strlenflist = []
		self.memcpyflist = []

		# list of [func_addr, func_name, func_end_insn_addr]
		self.func_list = []
		# func_name to [func_addr, func_end_insn_addr]
		self.func_name_map = {}
		# func_addr to [func_name, func_end_insn_addr]
		self.func_addr_map = {}


		# [insn_addr, gv_addr, access_type]
		# access type: 1 for read, 2 for write, 3 for w/r
		self.gv_list = []
		# access insn address to [[gv_addr, access_type]]
		self.gv_map = {}
		# gv_addr to [[insn_addr, access_type]]
		self.gv_reverse_map = {}

		# list of [call_insn_addr, call_target_addr]
		# -1 for unsolved target address
		self.callinsn = []
		# call_insn_addr to call_target_addr map
		# -1 for unsolved target address
		self.callinsnmap = {}

		# list of [jmp_insn_addr, jmp_target_addr, type]
		# -1 for unsolved target address
		# type: 0 for direct, 1 for indirect
		self.jmpinsn = []

		# jmp_insn_addr to [jmp_target_addr, type] map
		# type: 0 for direct, 1 for indirect
		self.jmpinsnmap = {}

		# back edge jmp_insn_addr to jmp_target_addr map
		self.backedgemap = {}

		# list of control instruction addresses
		self.controlinsn = []

		# func_addr to [[callsite_addr, callee_addr]]
		self.callgraph = {}

		# callee_addr to [[caller_addr, callsite_addr]]
		self.callgraph_reverse = {}

		self.hasmutex = 0
		self.hasspin = 0


		self.locksiteaddr = []
		# lock site addr to [lock_var_addr, type, transfer_type]
		# lock_var_addr: -1 for unsolved
		# type: 0 for sgx_thread_mutex_lock, 1 for sgx_thread_mutex_unlock, 2 for sgx_spin_lock, 3 for sgx_spin_unlock
		# transfer_type: 0 for call, 1 for jmp
		self.locksite = {}

		# insn_addr to [sucessors]
		# for all instructions from objdump
		self.insn_suc_map = {}

		# insn_addr to a set of lock_variable_addr
		self.lockset = {}

		# func_addr to the number of sgx_thread_mutex_lock called
		self.func_mutex_lock_count_map = {}

		# func_addr to the number of sgx_thread_mutex_unlock called
		self.func_mutex_unlock_count_map = {}

		# func_addr to the number of sgx_spin_lock called
		self.func_spin_lock_count_map = {}

		# func_addr to the number of sgx_spin_unlock called
		self.func_spin_unlock_count_map = {}

		self.whitelist = []

		# insn_addr to [[suc_addr, type]]
		# suc_addr: -1 if unsolved
		# type: 0 for intra, 1 for call, 2 for intra-jmp, 3 for inter-jmp, 4 for ret
		self.insn_successor_map = {}

		# a map to a set of locks
		self.callee_root_function_to_lockset_map = {}
		# a map to a set of caller function addresses
		self.callee_root_function_to_caller_map = {}
		# a map to a set of call site addresses
		self.callee_root_function_to_callsite_map = {}
		self.callee_root_function_to_functions_map = {}

		# a list of racing pairs, each pair has two accesses, each access has gv_addr, insn_addr and access_type, and a exploitable type
		# exploitable type: 0 for benign, 1 for data violation, 2 for control flow bending, 3 for both
		# [[[gv_addr, insn_addr1, access_type1], [gv_addr, insn_addr2, access_type2], exploitable_type]]
		self.race_sites_list = []

		# global variable address to racing pairs map
		# gv_addr to [[[gv_addr, insn_addr1, access_type1], [gv_addr, insn_addr2, access_type2], exploitable_type]]
		self.race_sites_map = {}

		self.mutex_lock_functions = ["sgx_thread_mutex_lock", "pthread_mutex_lock", "oe_pthread_mutex_lock", "mbedtls_mutex_lock", "oe_mutex_lock"]
		self.mutex_unlock_functions = ["sgx_thread_mutex_unlock", "pthread_mutex_unlock", "oe_pthread_mutex_unlock", "mbedtls_mutex_unlock", "oe_mutex_unlock"]
		self.spin_lock_functions = ["sgx_spin_lock", "oe_pthread_spin_lock", "oe_spin_lock"]
		self.spin_unlock_functions = ["sgx_spin_unlock", "oe_pthread_spin_unlock", "oe_spin_unlock"]

		self.start1 = 0
		self.start2 = 0
		self.end1 = 0
		self.end2 = 0

		# a list of [section_name, section_type, section_address, section_offset, section_size]
		self.sectionsinfo = []

		# a dict from section_offset to [section_name, section_type, section_address, section_offset, section_size]
		self.sectionsinfo_offset_map = {}

		# a dict from section_name to [section_name, section_type, section_address, section_offset, section_size]
		self.sectionsinfo_name_map = {}

		# a dict from hexdump start offset of each line to its line index in the file, starting from 0
		self.hexdump_start_offset_to_line_index_map = {}

		self.MAX_ITERATE = 10
		self.MAX_SINGLE_ITERATE = 2

		self.loop_times_map = {}

		self.mallocfunctionaddrs = []

		# heap variable allocation inst addr to [return func] map
		#self.heapvar_to_retfunc_map = {}

		# return func to [heap variable allocation inst addr] map
		#self.retfunc_to_heapvar_map = {}

		# heap variable pointer containing global variable to [heap_var_init_insn_addr]
		self.gvtohv_map = {}
		# heap_var_init_insn_addr to [heap variable pointer containing global variable]
		self.hvtogv_map = {}

		# a set of func addr that involves heap pointer reading
		self.heap_pointer_access_func_addrs = set()
		# insn_addr to [[heap_pointer, access_type]]
		self.heap_pointer_access_insn_map = {}
		# func addr to a set of gv_addr map
		self.heap_pointer_access_func_addr_to_gv_map = {}

		# a set of memory cell addrs
		self.track_cells = set()

		self.init_track_cells_at_beginning = False

		self.heap_init_funcs = set()

		# a coarse grained gv addr to name str map
		self.coarsegvmap = {}

		# insn addr to [gv_addr, constant] map
		self.constantwritemap = {}

		# insn addr to (lock_addr to a set of locks map) map
		self.lockhistory = {}

		# list of none-code addresses in code section
		self.nonecodeaddresses = []

		# a caller to a set of callees map via calling off-the-shelf once functions
		self.ots_once_caller_callee_map = {}

		self.intel_sgx_sdk_func_names = []
		self.intel_sgx_sdk_func_insn_addrs = []

		# data section names
		self.data_section_names = [".rodata", ".niprod", ".nipd", ".bss", ".tbss", ".data.rel.ro", ".data"]
		# a list of [data section name, start_addr, end_addr]
		self.data_section_info = []

		# the max v_dyn_addr of all data sections, for quick check use
		self.data_sections_v_dyn_addr_max = None
		# the min v_dyn_addr of all data sections, for quick check use
		self.data_sections_v_dyn_addr_min = None
		
global info
info = Info()



def load_binary():

	#comm = "file " + info.args.input
	#print(os.system(comm))

	#print(subprocess.check_output(['file', info.args.input]).decode('utf-8'))

	file_command_return_string = subprocess.check_output(['file', info.args.input]).decode('utf-8')


	#if info.args.input.endswith(".so"):
	if "shared object" in file_command_return_string and "dynamically linked" in file_command_return_string:
		info.picflag = 1
	else:
		info.picflag = 0

	if info.picflag == 1:
		try:
			info.project = angr.Project(info.args.input,load_options={'auto_load_libs': False})
		except:
			info.picflag = 0
			info.project = angr.Project(info.args.input, 
				main_opts = {'backend': 'blob', 'custom_arch': 'amd64'},
				load_options={'auto_load_libs': False})
	elif info.picflag == 0:
		info.project = angr.Project(info.args.input, 
			main_opts = {'backend': 'blob', 'custom_arch': 'amd64'},
			load_options={'auto_load_libs': False})

	#print(hex(info.picflag))


#
# the objdump generated diassembly file is named with original_file_name_asm in the same directory
# the hexdump generated file and readelf generated section info are also in the same directory
#
def disassemble():
	info.binaryfile = os.path.realpath(info.args.input)

	# generate objdump file
	info.asmfile = info.binaryfile + "_asm"
	#print(info.asmfile)
	tmpfile = "/tmp/" + os.path.basename(info.asmfile)
	#print(tmpfile)
	comm = "objdump -d " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.asmfile) and not filecmp.cmp(tmpfile, info.asmfile)) or not os.path.exists(info.asmfile):
			comm = "objdump -d " + info.binaryfile + " > " + info.asmfile
			os.system(comm)

	# generate hexdump file
	info.hexdumpfile = info.binaryfile + "_hexdump"
	#print(info.hexdumpfile)
	tmpfile = "/tmp/" + os.path.basename(info.hexdumpfile)
	#print(tmpfile)
	comm = "hexdump -C " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.hexdumpfile) and not filecmp.cmp(tmpfile, info.hexdumpfile)) or not os.path.exists(info.hexdumpfile):
			comm = "hexdump -C " + info.binaryfile + " > " + info.hexdumpfile
			os.system(comm)

	# generate readelf section info file
	info.readelffile = info.binaryfile + "_readelf"
	#print(info.readelffile)
	tmpfile = "/tmp/" + os.path.basename(info.readelffile)
	#print(tmpfile)
	comm = "readelf -S " + info.binaryfile + " > " + tmpfile
	os.system(comm)
	if os.path.exists(tmpfile):
		if (os.path.exists(info.readelffile) and not filecmp.cmp(tmpfile, info.readelffile)) or not os.path.exists(info.readelffile):
			comm = "readelf -S " + info.binaryfile + " > " + info.readelffile
			os.system(comm)
	

def readelfsectionsinfo():
	f1 = open(info.readelffile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "[" in line1 and "]" in line1:
			#print(line1[line1.index("[") + 1:line1.index("]")])
			s = line1[line1.index("[") + 1:line1.index("]")].strip()
			if s.isnumeric():
				#print(str(int(s, 10)))
				nextline1 = lines1[lines1.index(line1) + 1]
				nextline1split = nextline1.strip().split()
				#print(line1)
				#print(nextline1)
				restline1 = line1[line1.index("]") + 1:].strip().split()
				#print(restline1)

				if len(restline1) == 4:
					#print(line1)
					#print(restline1[0])
					#print(restline1[3])
					#print(nextline1split[0])

					info.sectionsinfo.append([restline1[0], restline1[1], int(restline1[2], 16), int(restline1[3], 16), int(nextline1split[0], 16)])
					info.sectionsinfo_offset_map[int(restline1[3], 16)] = [restline1[0], restline1[1], int(restline1[2], 16), int(restline1[3], 16), int(nextline1split[0], 16)]
					info.sectionsinfo_name_map[restline1[0]] = [restline1[0], restline1[1], int(restline1[2], 16), int(restline1[3], 16), int(nextline1split[0], 16)]
	f1.close()

	#for sectioninfo in info.sectionsinfo:
	#	print("*")
	#	print(sectioninfo[0])
	#	print(sectioninfo[1])
	#	print(hex(sectioninfo[2]))
	#	print(hex(sectioninfo[3]))
	#	print(hex(sectioninfo[4]))

	#for sectioninfo_offset in info.sectionsinfo_offset_map:
	#	print("*")
	#	print(info.sectionsinfo_offset_map[sectioninfo_offset][0])
	#	print(info.sectionsinfo_offset_map[sectioninfo_offset][1])
	#	print(hex(info.sectionsinfo_offset_map[sectioninfo_offset][2]))
	#	print(hex(info.sectionsinfo_offset_map[sectioninfo_offset][3]))
	#	print(hex(info.sectionsinfo_offset_map[sectioninfo_offset][4]))

	# resolve data sections
	for sectioninfo in info.sectionsinfo:
		#print("*")
		#print(sectioninfo[0])
		##print(sectioninfo[1])
		#print(hex(sectioninfo[2]))
		##print(hex(sectioninfo[3]))
		#print(hex(sectioninfo[4]))
		start_v_dyn_addr = static_addr_to_v_dyn_addr(sectioninfo[2])
		end_v_dyn_addr = static_addr_to_v_dyn_addr(sectioninfo[2] + sectioninfo[4] - 1)
		#print(hex(start_v_dyn_addr))
		#print(hex(end_v_dyn_addr))

		if sectioninfo[0] in info.data_section_names:
			info.data_section_info.append([sectioninfo[0], start_v_dyn_addr, end_v_dyn_addr])

			if info.data_sections_v_dyn_addr_min == None or start_v_dyn_addr < info.data_sections_v_dyn_addr_min:
				info.data_sections_v_dyn_addr_min = start_v_dyn_addr

			if info.data_sections_v_dyn_addr_max == None or end_v_dyn_addr > info.data_sections_v_dyn_addr_max:
				info.data_sections_v_dyn_addr_max = end_v_dyn_addr

	
	#for data_sec_info in info.data_section_info:
	#	print("*")
	#	print(data_sec_info[0])
	#	print(hex(data_sec_info[1]))
	#	print(hex(data_sec_info[2]))
	#print(hex(info.data_sections_v_dyn_addr_min))
	#print(hex(info.data_sections_v_dyn_addr_max))


# check wether a variable dynamic address used by angr (for symbolic execution use) is within data sections
def v_dyn_addr_in_data_sections(addr):
	if addr > info.data_sections_v_dyn_addr_max or addr < info.data_sections_v_dyn_addr_min:
		return False
	for data_sec_info in info.data_section_info:
		sec_start = data_sec_info[1]
		sec_end = data_sec_info[2]
		if addr >= sec_start and addr <= sec_end:
			return True
	return False


def readhexdumpinfo():
	#print("readhexdumpinfo")
	f1 = open(info.hexdumpfile,'r')
	lines1 = f1.readlines()
	line1_index = 0
	for line1 in lines1:
		#print(line1_index)
		s = line1.strip().split()
		if s[0] != "*":
			info.hexdump_start_offset_to_line_index_map[int(s[0], 16)] = line1_index
		line1_index = line1_index + 1
	f1.close()

	#for start_offset in sorted(info.hexdump_start_offset_to_line_index_map):
	#	print("*")
	#	print(hex(start_offset))
	#	print(str(info.hexdump_start_offset_to_line_index_map[start_offset]))


# convert variable dynamic address used by angr (for symbolic execution use)
# to static variable address (address defined in the binary) by just minus
# 0x400000 (for shared object)
def v_dyn_addr_to_static_addr(v_addr):
	file_command_return_string = subprocess.check_output(['file', info.args.input]).decode('utf-8')
	if "shared object" in file_command_return_string and "dynamically linked" in file_command_return_string:
		info.picflag = 1
	else:
		info.picflag = 0

	if info.picflag == 1:
		return v_addr - 0x400000
	else:
		return v_addr


def static_addr_to_v_dyn_addr(s_addr):
	file_command_return_string = subprocess.check_output(['file', info.args.input]).decode('utf-8')
	if "shared object" in file_command_return_string and "dynamically linked" in file_command_return_string:
		info.picflag = 1
	else:
		info.picflag = 0

	if info.picflag == 1:
		return s_addr + 0x400000
	else:
		return s_addr





# convert variable dynamic address used by angr (for symbolic execution use)
# to offset in the binary. if the variable address is not defined in the
# binary, return -1
def v_dyn_addr_to_binary_offset(v_addr):
	# convert v_addr to v_static_addr
	v_static_addr = v_dyn_addr_to_static_addr(v_addr)

	for sectioninfo in info.sectionsinfo:
		if sectioninfo[2] != 0:
			# find it.
			if v_static_addr >= sectioninfo[2] and v_static_addr <= sectioninfo[2] + sectioninfo[4] - 1:
				return v_static_addr - (sectioninfo[2] - sectioninfo[3])
	return -1


# return None if not inside any section
def get_variable_section(v_addr):
	# convert v_addr to offset in binary
	offset = v_dyn_addr_to_binary_offset(v_addr)

	if offset == -1:
		return None

	# convert v_addr to v_static_addr
	v_static_addr = v_dyn_addr_to_static_addr(v_addr)

	for sectioninfo in info.sectionsinfo:
		if v_static_addr >= sectioninfo[2] and v_static_addr <= sectioninfo[2] + sectioninfo[4] - 1:
			return sectioninfo[0]

	return None


# currently supports read from within aligned 16 bytes
# call v_dyn_addr_to_binary_offset and check whether it is -1 before calling this function
# currently width parameter should not be larger than 16
# default endian is little endian, which is True
def read_variable_initial_value_in_binary(v_addr, width, little_endian = True):
	#print("v_addr:")
	#print(hex(v_addr))
	#print("width:")
	#print(hex(width))

	# convert v_addr to offset in binary
	v_offset = v_dyn_addr_to_binary_offset(v_addr)
	v_aligned_start_offset = v_offset - v_offset % 16
	v_aligned_remaining_offset = v_offset % 16

	# in case someone forgets to call v_dyn_addr_to_binary_offset
	if v_offset == -1:
		return -1

	#print("v_aligned_start_offset:")
	#print(hex(v_aligned_start_offset))
	if get_variable_section(v_addr) == ".bss":
		return 0x0
	else:
		resultline1 = None
		f1 = open(info.hexdumpfile,'r')
		lines1 = f1.readlines()
		if v_aligned_start_offset in info.hexdump_start_offset_to_line_index_map:
			line1_index = info.hexdump_start_offset_to_line_index_map[v_aligned_start_offset]
			resultline1 = lines1[line1_index]
		else:
			current_offset = v_aligned_start_offset - 0x10
			while current_offset >= 0:
				if current_offset in info.hexdump_start_offset_to_line_index_map:
					line1_index = info.hexdump_start_offset_to_line_index_map[current_offset]
					resultline1 = lines1[line1_index]
					break
				current_offset = current_offset - 0x10

		containingbytes = resultline1.strip().split()[1:16]
		#print("containingbytes:")
		#print(containingbytes)

		final_num_str = ""
		byte_start_index = v_aligned_remaining_offset

		#print("byte_start_index:")
		#print(str(byte_start_index))

		b_index = 0

		num_str_list = []
		for b in containingbytes:
			#print("b_index:")
			#print(str(b_index))
			if b_index >= byte_start_index and b_index <= byte_start_index + width - 1:
				num_str_list.append(b)

			b_index = b_index + 1

		#print("num_str_list:")
		#print(num_str_list)

		if little_endian:
			num_str_list = reversed(num_str_list)

		for num_str in num_str_list:
			#print("num_str:")
			#print(num_str)
			final_num_str = final_num_str + num_str

		#print("final_num_str:")
		#print(final_num_str)
		final_num = int(final_num_str, 16)

		return final_num



def parseinsaddr(line, separator):
	temp = line[:line.find(separator)]
	try:
		temp1 = int(temp, 16)
	except:
		return -1


	if info.picflag == 1:
		temp2 = temp1 + 0x400000
	else:
		temp2 = temp1
	return temp2


def checkzeropadding(line, separator):
	temp = line[line.find(separator)+1:]
	if "\t" in temp:
		temp = temp[line.find("\t")+1:]
		if "\t" in temp:
			return False
	return True


def findinsaddr():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if ":" in line1:
			addr = parseinsaddr(line1, ":")
			if addr == -1:
				continue
			if checkzeropadding(line1, ":") == False:
				info.insnaddrs.append(addr)
				info.insnlinesmap[addr] = line1
	f1.close()

	#for ad in info.insnaddrs:
	#	print(hex(ad))

	#for addr in sorted(info.insnlinesmap):
	#	print("*")
	#	print(hex(addr))
	#	print(info.insnlinesmap[addr])


def findnextinsaddr(addr):
	if addr >= info.insnaddrs[-1] or addr < info.insnaddrs[0]:
		return -1
	try:
		return info.insnaddrs[info.insnaddrs.index(addr) + 1]
	except:
		return -1


def findpreviousinsaddr(addr):
	if addr > info.insnaddrs[-1] or addr <= info.insnaddrs[0]:
		return -1
	try:
		return info.insnaddrs[info.insnaddrs.index(addr) - 1]
	except:
		return -1


def getinsaddr(line, separator):
	temp = line[:line.find(separator)]
	temp1 = int(temp, 16)
	if info.picflag == 1:
		temp2 = temp1 + 0x400000
	else:
		temp2 = temp1
	return temp2


#
# search disassembly for unsupported instructions
#
# unsupported instructions:
# xsave
# xsavec
# xsaves
# xsave64
# xsavec64
# xsaves64
# fxsave
# fxsave64
# xrstor
# xrstors
# xrstor64
# xrstors64
# fxrstor
# fxrstor64
#
# rep stos
# rep movsq
#
# rdrand
# wrfsbase
#
def findunsupportedinstructions():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "\txsave " in line1:
			addr = getinsaddr(line1, ":")
			info.xsavelist.append(addr)
			info.unsupportedlist.append(addr)
		if "\txsavec " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaveclist.append(addr)
			info.unsupportedlist.append(addr)
		if "\txsaves " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaveslist.append(addr)
			info.unsupportedlist.append(addr)
		if "\txsave64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsave64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\txsavec64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsavec64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\txsaves64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xsaves64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\tfxsave " in line1:
			addr = getinsaddr(line1, ":")
			info.fxsavelist.append(addr)
			info.unsupportedlist.append(addr)
		if "\tfxsave64 " in line1:
			addr = getinsaddr(line1, ":")
			info.fxsave64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\txrstor " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstorlist.append(addr)
			info.unsupportedlist.append(addr)
		if "\txrstors " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstorslist.append(addr)
			info.unsupportedlist.append(addr)
		if "\txrstor64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstor64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\txrstors64 " in line1:
			addr = getinsaddr(line1, ":")
			info.xrstors64list.append(addr)
			info.unsupportedlist.append(addr)
		if "\tfxrstor " in line1:
			addr = getinsaddr(line1, ":")
			info.fxrstorlist.append(addr)
			info.unsupportedlist.append(addr)
		if "\tfxrstor64 " in line1:
			addr = getinsaddr(line1, ":")
			info.fxrstor64list.append(addr)
			info.unsupportedlist.append(addr)

		#
		# TBD: rep, stos
		#
		if "\trep stos " in line1:
			addr = getinsaddr(line1, ":")
			info.repstoslist.append(addr)
			info.unsupportedlist.append(addr)

		if "\trep movsq " in line1:
			addr = getinsaddr(line1, ":")
			info.repmovsqlist.append(addr)
			info.unsupportedlist.append(addr)

		if "\trdrand " in line1 and not "<" in line1:
			addr = getinsaddr(line1, ":")
			info.rdrandlist.append(addr)
			info.unsupportedlist.append(addr)

		if "\twrfsbase " in line1 and not "<" in line1:
			addr = getinsaddr(line1, ":")
			info.wrfsbaselist.append(addr)
			info.unsupportedlist.append(addr)

		if "call" in line1 and "<strlen>" in line1:
			addr = getinsaddr(line1, ":")
			info.strlenflist.append(addr)
			info.unsupportedlist.append(addr)

		if "call" in line1 and "<memcpy>" in line1:
			addr = getinsaddr(line1, ":")
			info.memcpyflist.append(addr)
			info.unsupportedlist.append(addr)



	f1.close()
	gc.collect()

	#for usi in info.unsupportedlist:
	#	print(hex(usi))


def capstoneparse():
	start = info.insnaddrs[0]
	while True:
		if start == info.insnaddrs[0]:
			addr = start
		else:
			while start <= info.insnaddrs[-1]:
				addr = findnextinsaddr(start)
				if addr >= info.insnaddrs[0] and addr <= info.insnaddrs[-1]:
					break
				else:
					start = start + 1

		if start < info.insnaddrs[0] or start > info.insnaddrs[-1]:
			break

		#print("capstone disassembly starts: " + hex(addr))
		with open(info.args.input, 'rb') as f:
			if info.picflag == 1:
				seekstart = addr - 0x400000
			else:
				seekstart = addr
			#print("*")
			#print(hex(addr))
			#seekstart = 0xd940
			#print(hex(seekstart))

			# if text section address and offset are not the same
			for sectioninfo in info.sectionsinfo:
				if sectioninfo[0] == ".text" and sectioninfo[2] != sectioninfo[3]:
					seekstart = seekstart - (sectioninfo[2] - sectioninfo[3])


			f.seek(seekstart, 1)
			info.code = f.read()
			insns = info.project.arch.capstone.disasm(info.code, addr)
			#md = Cs(CS_ARCH_X86, CS_MODE_64)
			#for i in md.disasm(info.code, 0xe940):
			#	print(i.mnemonic)
			insnlist = list(insns)

			# disassemble as many instructions as objdump
			templist = list(insnlist)
			for csinsn in templist:
				if csinsn.address > info.insnaddrs[-1]:
					insnlist.remove(csinsn)

			info.insns.extend(insnlist)
			for ins in insnlist:
				info.insnsmap[ins.address] = ins
				#print(hex(ins.address))
				#print(ins.mnemonic)
			gc.collect()

		f.close()

		if insnlist:
			start = insnlist[-1].address
		else:
			start = addr
		#print("start: " + hex(start))
		gc.collect()
	gc.collect()

	#for csinsn in info.insns:
	#	print("*")
	#	print(hex(csinsn.address))
	#	print(csinsn.mnemonic)
	#	print(csinsn.op_str)
	#	print(csinsn.size)


def findenclu():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "enclu" in line1:
			addr = getinsaddr(line1, ":")
			info.enclulist.append(addr)
			#print(hex(addr))
	f1.close()


def findenclaveentry():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "<enclave_entry>:" in line1 or "<oe_enter>:" in line1 or "<sgx_entry>:" in line1:
			info.enclaveentry = getinsaddr(line1, "<")
			break
	f1.close()

	#print(hex(info.enclaveentry))


def findabortfunction():
	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "<abort>:" in line1 or "<__rust_abort>:" in line1:
			info.abortfunction = getinsaddr(line1, "<")
			break
	f1.close()

	#print(hex(info.abortfunction))


def findaddresses():
	findenclu()
	findenclaveentry()
	findabortfunction()


def passf(state):
	pass


def strnlenf(state):
	state.rip = 0x1563b


def handleaddresses():
	for addr in info.xsavelist:
		info.project.hook(addr, passf, length=3)
	for addr in info.xsaveclist:
		info.project.hook(addr, passf, length=3)
	for addr in info.xsaveslist:
		info.project.hook(addr, passf, length=3)
	for addr in info.xsave64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.xsavec64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.xsaves64list:
		info.project.hook(addr, passf, length=4)
	if info.picflag == 1:
		for addr in info.fxsavelist:
			info.project.hook(addr, passf, length=3)
	else:
		for addr in info.fxsavelist:
			info.project.hook(addr, passf, length=4)

	for addr in info.fxsave64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.xrstorlist:
		info.project.hook(addr, passf, length=4)
	for addr in info.xrstorslist:
		info.project.hook(addr, passf, length=4)
	for addr in info.xrstor64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.xrstors64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.fxrstorlist:
		info.project.hook(addr, passf, length=4)
	for addr in info.fxrstor64list:
		info.project.hook(addr, passf, length=4)
	for addr in info.repstoslist:
		info.project.hook(addr, passf, length=2)
	for addr in info.repmovsqlist:
		info.project.hook(addr, passf, length=3)

	# TBD: rdrand
	for addr in info.rdrandlist:
		info.project.hook(addr, passf, length=3)

	for addr in info.wrfsbaselist:
		info.project.hook(addr, passf, length=5)

	'''
	# sgx_ocalloc
	info.project.hook_symbol("sgx_ocalloc", Ocalloc())
	info.project.hook_symbol("memcopy", Memcopy())
	info.project.hook_symbol("memmove", Memmove())
	'''

	'''
	info.project.hook(0x101af, passf, length = 2)
	info.project.hook(0x7108, passf, length = 5)
	info.project.hook(0x7114, passf, length = 5)
	info.project.hook(0x11077, passf, length = 5)
	info.project.hook(0x11060, passf, length = 5)
	info.project.hook(0x110a1, passf, length = 5)
	info.project.hook(0x110c0, passf, length = 5)
	info.project.hook(0x1103e, passf, length = 5)
	info.project.hook(0x15570, strnlenf, length = 1)
	info.project.hook(0x11031, passf, length = 5)
	info.project.hook(0x1155e, passf, length = 5)
	'''

	
	for addr in info.strlenflist:
		info.project.hook(addr, passf, length=5)
	for addr in info.memcpyflist:
		info.project.hook(addr, passf, length=5)


def findfunctions():

	templist = []

	f1 = open(info.asmfile,'r')
	lines1 = f1.readlines()
	for line1 in lines1:
		if "<" in line1 and ">:" in line1:
			func_name = line1[line1.index("<") + 1:line1.index(">")]
			#print(str(line1.index("<")))
			#print(str(line1.index(">")))
			#print(func_name)
			temp = int(line1[:line1.index("<")], 16)
			func_addr = 0
			if info.picflag == 1:
				func_addr = temp + 0x400000
			else:
				func_addr = temp
			
			templist.append([func_addr, func_name])

	f1.close()

	count = len(templist)
	index = 1

	for addr in info.insnaddrs:
		if index == count:
			break

		if addr >= templist[index][0]:
			func_end_addr = info.insnaddrs[info.insnaddrs.index(addr) - 1]
			info.func_list.append([templist[index - 1][0], templist[index - 1][1], func_end_addr])
			index = index + 1

	info.func_list.append([templist[count - 1][0], templist[count - 1][1], info.insnaddrs[-1]])

	# to handle name duplicates
	#func_name_set = set()
	#dup_name_set = set()
	#for f in info.func_list:
	#	if f[1] in func_name_set:
	#		dup_name_set.add(f[1])
	#	func_name_set.add(f[1])

	for f in info.func_list:
		#if f[1] in dup_name_set:
		#	info.func_name_map[f[1] + "_FUNCADDR_" + hex(f[0])] = [f[0], f[2]]
		#else:
		#	info.func_name_map[f[1]] = [f[0], f[2]]
		info.func_name_map[f[1]] = [f[0], f[2]]
		info.func_addr_map[f[0]] = [f[1], f[2]]
	
	gc.collect()

	#for f in info.func_list:
	#	print("*")
	#	print(f[1])
	#	print(hex(f[0]))
	#	print(hex(f[2]))

	#for name in info.func_name_map:
	#	print("*")
	#	print(name)
	#	print(hex(info.func_name_map[name][0]))
	#	print(hex(info.func_name_map[name][1]))


def get_enclosing_func_addr(addr):
	for name in info.func_name_map:
		if addr >= info.func_name_map[name][0] and addr <= info.func_name_map[name][1]:
			return info.func_name_map[name][0]
	return -1

def get_enclosing_func_addr_1(addr):
	for f in info.func_list:
		if addr >= f[0] and addr <= f[2]:
			return f[0]
	return -1

def get_enclosing_func_name_1(addr):
	for f in info.func_list:
		if addr >= f[0] and addr <= f[2]:
			return f[1]
	return -1


def get_enclosing_func_end_addr(addr):
	for name in info.func_name_map:
		if addr >= info.func_name_map[name][0] and addr <= info.func_name_map[name][1]:
			return info.func_name_map[name][1]
	return -1


def get_enclosing_func_end_addr_1(addr):
	for f in info.func_list:
		if f[0] == addr:
			return f[2]
	return -1


def findcallinsn():
	for addr in sorted(info.insnsmap):
		insn = info.insnsmap[addr]
		#print(str(insn.id))
		#print(insn.mnemonic)
		if insn.id == X86_INS_CALL:
			if insn.operands[0].type == X86_OP_IMM:
				#print(hex(insn.address))
				#print(hex(insn.operands[0].value.imm))
				info.callinsn.append([insn.address, insn.operands[0].value.imm])
				info.callinsnmap[insn.address] = insn.operands[0].value.imm
			else:
				info.callinsn.append([insn.address, -1])
				info.callinsnmap[insn.address] = -1
	
	#for callinsn in info.callinsn:
	#	print("*")
	#	print(hex(callinsn[0]))
	#	print(hex(callinsn[1]))
	

def findjmpinsn():
	for addr in sorted(info.insnsmap):
		insn = info.insnsmap[addr]
		#print(str(insn.id))
		#print(insn.mnemonic)
		if insn.id >= X86_INS_JAE and insn.id <= X86_INS_JS:
			if insn.id == X86_INS_JMP:
				if insn.operands[0].type == X86_OP_IMM:
					#print(hex(insn.address))
					#print(hex(insn.operands[0].value.imm))
					info.jmpinsn.append([insn.address, insn.operands[0].value.imm, 0])
					info.jmpinsnmap[insn.address] = [insn.operands[0].value.imm, 0]
				else:
					info.jmpinsn.append([insn.address, -1, 0])
					info.jmpinsnmap[insn.address] = [-1, 0]
			else:
				if insn.operands[0].type == X86_OP_IMM:
					#print(hex(insn.address))
					#print(hex(insn.operands[0].value.imm))
					info.jmpinsn.append([insn.address, insn.operands[0].value.imm, 1])
					info.jmpinsnmap[insn.address] = [insn.operands[0].value.imm, 1]
				else:
					info.jmpinsn.append([insn.address, -1, 1])
					info.jmpinsnmap[insn.address] = [-1, 1]
	
	#for jmpinsn in info.jmpinsn:
	#	print("*")
	#	print(hex(jmpinsn[0]))
	#	print(hex(jmpinsn[1]))
	

def findcontrolinsn():
	for addr in sorted(info.insnsmap):
		insn = info.insnsmap[addr]
		#print(str(insn.id))
		#print(insn.mnemonic)
		if (insn.id >= X86_INS_JAE and insn.id <= X86_INS_JS) or insn.id == X86_INS_CALL or insn.id == X86_INS_RET or insn.id == X86_INS_RETF or insn.id == X86_INS_RETFQ:
			info.controlinsn.append(insn.address)
			#print(hex(insn.address))
			#print(insn.mnemonic)
			#print(str(insn.id))
	
	#for controlinsn in info.controlinsn:
	#	print(hex(controlinsn))


def findbackedges():
	for insn in info.jmpinsn:
		#print("*")
		#print(hex(insn[0]))
		#print(hex(insn[1]))
		#print(hex(get_enclosing_func_addr(insn[0])))
		#print(hex(get_enclosing_func_end_addr(insn[0])))
		jmp_addr = insn[0]
		jmp_target_addr = insn[1]
		enclosing_func_addr = get_enclosing_func_addr(insn[0])
		if jmp_target_addr != -0x1 and jmp_target_addr < jmp_addr and enclosing_func_addr != -0x1 and jmp_target_addr >= enclosing_func_addr:
			info.backedgemap[jmp_addr] = jmp_target_addr
	
	#for addr in sorted(info.backedgemap):
	#	print("*")
	#	print(hex(addr))
	#	print(hex(info.backedgemap[addr]))
	

# return the bb start address
def get_enclosing_bb_addr(addr):
	if addr < info.insnaddrs[0] or addr > info.insnaddrs[-1]:
		return -1
	#for controlinsn in sorted(info.controlinsn, reverse = True):
	#	if addr > controlinsn:
	#		return findnextinsaddr(controlinsn)
	#return -1

	insn = addr
	while ((not insn in info.controlinsn or (insn in info.controlinsn and insn == addr)) and (insn != get_enclosing_func_addr_1(insn)) and (insn != -1)):
		insn = findpreviousinsaddr(insn)

	if insn in info.controlinsn:
		#print(hex(addr))
		#print(hex(insn))
		#print(hex(findnextinsaddr(insn)))
		return findnextinsaddr(insn)
	elif insn == get_enclosing_func_addr_1(insn):
		return insn
	else:
		return -1







# return the bb end address, i.e., next control instruction address
def get_enclosing_bb_end_addr(addr):
	if addr < info.insnaddrs[0] or addr > info.insnaddrs[-1]:
		return -1
	for controlinsn in sorted(info.controlinsn, reverse = False):
		if addr < controlinsn:
			if get_enclosing_func_addr(addr) == get_enclosing_func_addr(controlinsn) and get_enclosing_func_addr(addr) != -1:
				return controlinsn
	return -1

def get_enclosing_bb_end_addr_1(addr):
	if addr < info.insnaddrs[0] or addr > info.insnaddrs[-1]:
		return -1
	for controlinsn in sorted(info.controlinsn, reverse = False):
		if addr < controlinsn:
			if get_enclosing_func_addr_1(addr) == get_enclosing_func_addr_1(controlinsn) and get_enclosing_func_addr_1(addr) != -1:
				return controlinsn
	return -1


def build_call_graph():
	for addr in sorted(info.callinsnmap):
		#print("*")
		#print(hex(addr))
		#print(hex(get_enclosing_func_addr_1(addr)))
		if info.callinsnmap[addr] != -1:
			if get_enclosing_func_addr_1(addr) in info.callgraph:
				info.callgraph[get_enclosing_func_addr_1(addr)].append([addr, info.callinsnmap[addr]])
			else:
				info.callgraph[get_enclosing_func_addr_1(addr)] = [[addr, info.callinsnmap[addr]]]

		if info.callinsnmap[addr] != -1:
			if info.callinsnmap[addr] in info.callgraph_reverse:
				info.callgraph_reverse[info.callinsnmap[addr]].append([get_enclosing_func_addr_1(addr), addr])
			else:
				info.callgraph_reverse[info.callinsnmap[addr]] = [[get_enclosing_func_addr_1(addr), addr]]

	#for addr in sorted(info.callgraph):
	#	print("*")
	#	print(hex(addr))
	#	for p in info.callgraph[addr]:
	#		print(hex(p[0]))
	#		print(hex(p[1]))


def findinsnsuccessors():
	info.succssorsfile = info.binaryfile + "_successors_tmp_file"

	if not os.path.exists(info.succssorsfile):
		for addr in info.insnaddrs:
			#print("+")
			#print(hex(addr))
			if addr not in info.insnsmap:
				#print(hex(addr))
				if addr == get_enclosing_func_end_addr(addr):
					info.insn_successor_map[addr] = [[-1, 4]]
				else:
					info.insn_successor_map[addr] = [[findnextinsaddr(addr), 0]]
			else:
				if info.insnsmap[addr].id == X86_INS_CALL:
					#print(hex(addr))
					info.insn_successor_map[addr] = [[info.callinsnmap[addr], 1]]
				elif info.insnsmap[addr].id == X86_INS_RET or info.insnsmap[addr].id == X86_INS_RETF or info.insnsmap[addr].id == X86_INS_RETFQ:
					#print(hex(addr))
					info.insn_successor_map[addr] = [[-1, 4]]
				elif info.insnsmap[addr].id >= X86_INS_JAE and info.insnsmap[addr].id <= X86_INS_JS:
					#print("*")
					#print(hex(addr))
					#print(info.insnsmap[addr].mnemonic)
					#print(hex(info.jmpinsnmap[addr][0]))
					#print(hex(info.jmpinsnmap[addr][1]))
					#print(hex(get_enclosing_func_addr(addr)))
					#print(hex(get_enclosing_func_end_addr(addr)))
					if info.jmpinsnmap[addr][1] == 0:
						if info.jmpinsnmap[addr][0] == -1:
							info.insn_successor_map[addr] = [[-1, 3]]
						else:
							if info.jmpinsnmap[addr][0] >= get_enclosing_func_addr(addr) and info.jmpinsnmap[addr][0] <= get_enclosing_func_end_addr(addr):
								info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 2]]
							else:
								info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 3]]
					else:
						if info.jmpinsnmap[addr][0] == -1:
							if addr == get_enclosing_func_end_addr(addr):
								info.insn_successor_map[addr] = [[-1, 3], [-1, 4]]
							else:
								info.insn_successor_map[addr] = [[-1, 3], [findnextinsaddr(addr), 0]]
						else:
							if info.jmpinsnmap[addr][0] >= get_enclosing_func_addr(addr) and info.jmpinsnmap[addr][0] <= get_enclosing_func_end_addr(addr):
								if addr == get_enclosing_func_end_addr(addr):
									info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 2], [-1, 4]]
								else:
									info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 2], [findnextinsaddr(addr), 0]]
							else:
								if addr == get_enclosing_func_end_addr(addr):
									info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 3], [-1, 4]]
								else:
									info.insn_successor_map[addr] = [[info.jmpinsnmap[addr][0], 3], [findnextinsaddr(addr), 0]]
				else:
					if addr == get_enclosing_func_end_addr(addr):
						info.insn_successor_map[addr] = [[-1, 4]]
					else:
						info.insn_successor_map[addr] = [[findnextinsaddr(addr), 0]]

		f = open(info.succssorsfile, "w")
		for addr in sorted(info.insn_successor_map):
			f.write("*\n")
			f.write(hex(addr) + "\n")
			for succ in info.insn_successor_map[addr]:
				f.write(hex(succ[0]) + "\n")
				f.write(hex(succ[1]) + "\n")
		f.close()

		#for addr in sorted(info.insn_successor_map):
		#	print("*")
		#	print(hex(addr))
		#	for succ in info.insn_successor_map[addr]:
		#		print(hex(succ[0]))
		#		print(hex(succ[1]))
		


	else:
		info.insn_successor_map = {}

		f = open(info.succssorsfile, "r")
		lines = f.readlines()

		key = None
		succs = []
		index = 0
		succ = []
		line_num = 0


		for line in lines:
			#print(line)
			if "*" in line:
				if key:
					#print(succs)
					info.insn_successor_map[key] = copy.deepcopy(succs)
					#print(info.insn_successor_map[key])
					key = None
					succs = []
					index = 0
			else:
				if index == 0:
					key = int(line, 16)
				else:
					if index % 2 == 1:
						succ = [int(line, 16)]
					else:
						succ.append(int(line, 16))
						succs.append(succ)
				index = index + 1

			if line_num == len(lines) - 1:
				if key:
					#print(succs)
					info.insn_successor_map[key] = copy.deepcopy(succs)
					#print(info.insn_successor_map[key])
					key = None
					succs = []
					index = 0

			line_num = line_num + 1

		f.close()
		#for addr in sorted(info.insn_successor_map):
		#	print("*")
		#	print(hex(addr))
		#	for succ in info.insn_successor_map[addr]:
		#		print(hex(succ[0]))
		#		print(hex(succ[1]))

def processwhitelist():
	for name in info.func_name_map:
		# intel sgx sdk, open enclave sdk, rust-sgx sdk
		if "sgx_thread_mutex" in name or "sgx_spin" in name or "sgx_thread_cond" in name \
			or "oe_once" in name or "oe_pthread_mutex" in name or "mbedtls_threading" in name or "mbedtls_mutex" in name or "threading_mutex" in name or "oe_mutex" in name \
			or "oe_pthread_spin" in name or "oe_spin" in name or "pthread_rwlock" in name or "oe_pthread_rwlock" in name or "oe_rwlock" in name \
			or "_rwlock_wrunlock" in name or "_rwlock_rdunlock" in name or "pthread_cond" in name or "oe_cond" in name \
			or "call_once" in name or "Barrier" in name or "Spinlock" in name or "Mutex" in name or "RwLock" in name or "Condvar" in name \
			or "oe_pthread_once" in name or "pthread_once" in name or "RWLock" in name:
			#print(name)
			info.whitelist.append(info.func_name_map[name][0])

	#for func_addr in info.whitelist:
	#	print(hex(func_addr))
	#	print(info.func_addr_map[func_addr][0])
	

def findmallocfunctionaddrs():
	for func_name in info.func_name_map:
		if func_name.endswith("alloc"):
			if func_name == "malloc" or func_name == "calloc" or func_name == "realloc" \
				or func_name == "dlmalloc" or func_name == "dlcalloc" or func_name == "dlrealloc" \
					or func_name == "oe_malloc" or func_name == "oe_calloc" or func_name == "oe_realloc" \
						or func_name == "__rust_alloc" or func_name == "__rust_realloc" or func_name == "__rust_alloc_zeroed":
						info.mallocfunctionaddrs.append(info.func_name_map[func_name][0])

	#for addr in info.mallocfunctionaddrs:
	#	print(hex(addr))


# get a coarse grained global variable addr to name string mapping
def findcoarsegvmapping():
	f = open(info.asmfile, "r")
	lines = f.readlines()

	for line in lines:
		if "#" in line and "<" in line and ">" in line:
			gv_name = line[line.index("<") + 1: line.index(">")]
			try:
				if info.picflag == 1:
					gv_addr = int(line[line.index("#") + 1: line.index("<")].strip(), 16) + 0x400000
				else:
					gv_addr = int(line[line.index("#") + 1: line.index("<")].strip(), 16)
				info.coarsegvmap[gv_addr] = gv_name
			except:
				pass
	f.close()

#	for gv_addr in sorted(info.coarsegvmap):
#		print("*")
#		print(hex(gv_addr))
#		print(info.coarsegvmap[gv_addr])
	


def findnonecode():
	for addr in sorted(info.insnlinesmap):
		#print(hex(addr))
		line = info.insnlinesmap[addr].strip()
		if "(bad)" in line and not "<" in line and not addr in info.nonecodeaddresses:
			#print(line)
			addr_start = addr
			addr_end = get_enclosing_func_end_addr(addr)
			#addr_end = get_enclosing_func_end_addr_1(addr)

			#print(hex(addr_end))
			#print(hex(get_enclosing_func_end_addr(addr)))

			addr_index = addr_start
			while addr_index <= addr_end:
				info.nonecodeaddresses.append(addr_index)
				addr_index = findnextinsaddr(addr_index)

	#for addr in info.nonecodeaddresses:
	#	print(hex(addr))


def findintelsgxsdkfuncnames():
	intelsgxsdkfuncnamesfile = "./config/intel_sgx_sdk_func_names_config"

	if os.path.exists(intelsgxsdkfuncnamesfile):
		f = open(intelsgxsdkfuncnamesfile, "r")
		lines = f.readlines()
		for line in lines:
			info.intel_sgx_sdk_func_names.append(line.strip())
		f.close()

	#for intel_sgx_sdk_func_name in info.intel_sgx_sdk_func_names:
	#	print(intel_sgx_sdk_func_name)


def findintelsgxsdkfuncinsnaddrs():
	for addr in info.insnaddrs:
		if info.func_addr_map[get_enclosing_func_addr_1(addr)][0] in info.intel_sgx_sdk_func_names:
			info.intel_sgx_sdk_func_insn_addrs.append(addr)

	#for intel_sgx_sdk_func_insn_addr in info.intel_sgx_sdk_func_insn_addrs:
	#	print(hex(intel_sgx_sdk_func_insn_addr))

	#for addr in info.insnaddrs:
	#	print(hex(addr))


def preprocessing():
	disassemble()
	readelfsectionsinfo()
	readhexdumpinfo()
	findinsaddr()
	capstoneparse()
	findunsupportedinstructions()
	findaddresses()
	handleaddresses()
	findfunctions()
	findcallinsn()
	findjmpinsn()
	findbackedges()
	findcontrolinsn()
	findinsnsuccessors()
	findmallocfunctionaddrs()
	findcoarsegvmapping()
	findnonecode()
	processwhitelist()
	build_call_graph()
	findintelsgxsdkfuncnames()
	findintelsgxsdkfuncinsnaddrs()


def global_variable_analysis_1():

	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("global_variable_analysis_1\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("global_variable_analysis_1")


	#print("global_variable_analysis_1")
	for insn in info.insns:


		if info.args.output2:
			print(hex(insn.address))
		#print(hex(insn.address))

		if info.args.app == True and insn.address in info.intel_sgx_sdk_func_insn_addrs:
			#print(hex(insn.address))
			continue

		# global interal

		if len(insn.operands) == 1:
			if insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.base != 0 and insn.operands[0].value.mem.index == 0 and insn.operands[0].value.mem.base == X86_REG_RIP:
				#print(hex(insn.address))
				#print(insn.mnemonic)
				if insn.id == X86_INS_INC:
					gv_addr_0 = findnextinsaddr(insn.address) + insn.operands[0].value.mem.disp
					if v_dyn_addr_in_data_sections(gv_addr_0) == True:
						if insn.address not in info.gv_map:
							info.gv_list.append([insn.address, gv_addr_0, 3])
							info.gv_map[insn.address] = [[gv_addr_0, 3]]
							if gv_addr_0 not in info.gv_reverse_map:
								info.gv_reverse_map[gv_addr_0] = [[insn.address, 3]]
							else:
								info.gv_reverse_map[gv_addr_0].append([insn.address, 3])
				else:
					gv_addr_0 = findnextinsaddr(insn.address) + insn.operands[0].value.mem.disp
					if v_dyn_addr_in_data_sections(gv_addr_0) == True:
						if insn.address not in info.gv_map:
							info.gv_list.append([insn.address, gv_addr_0, 1])
							info.gv_map[insn.address] = [[gv_addr_0, 1]]

							if gv_addr_0 not in info.gv_reverse_map:
								info.gv_reverse_map[gv_addr_0] = [[insn.address, 1]]
							else:
								info.gv_reverse_map[gv_addr_0].append([insn.address, 1])

		if len(insn.operands) == 2 and insn.id != X86_INS_LEA:
			op_access_0 = 0
			op_access_1 = 0
			gv_addr_0 = 0
			gv_addr_1 = 0

			if insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.base != 0 and insn.operands[0].value.mem.index == 0 and insn.operands[0].value.mem.base == X86_REG_RIP:
				#print("W")
				gv_addr_0 = findnextinsaddr(insn.address) + insn.operands[0].value.mem.disp
				if v_dyn_addr_in_data_sections(gv_addr_0) == True:
					op_access_0 = 1

				#print("*")
				#print(hex(findnextinsaddr(insn.address)))
				#print(hex(insn.operands[0].value.mem.disp))
				#print(hex(gv_addr_0))
			if insn.operands[1].type == X86_OP_MEM and insn.operands[1].value.mem.base != 0 and insn.operands[1].value.mem.index == 0 and insn.operands[1].value.mem.base == X86_REG_RIP:
				#print("R")
				gv_addr_1 = findnextinsaddr(insn.address) + insn.operands[1].value.mem.disp
				if v_dyn_addr_in_data_sections(gv_addr_1) == True:
					op_access_1 = 1

			if op_access_0 == 1:
				if (insn.id >= X86_INS_CMP and insn.id <= X86_INS_CMPXCHG8B) or insn.id == X86_INS_TEST or (insn.id >= X86_INS_BT and insn.id <= X86_INS_BTS):
					if insn.address not in info.gv_map:
						info.gv_list.append([insn.address, gv_addr_0, 1])
						info.gv_map[insn.address] = [[gv_addr_0, 1]]
						if gv_addr_0 not in info.gv_reverse_map:
							info.gv_reverse_map[gv_addr_0] = [[insn.address, 1]]
						else:
							info.gv_reverse_map[gv_addr_0].append([insn.address, 1])

				elif insn.id == X86_INS_MOVAPD or insn.id == X86_INS_MOVAPS or (insn.id >= X86_INS_MOVD and insn.id <= X86_INS_MOVQ) \
					 or (insn.id >= X86_INS_MOV and insn.id <= X86_INS_MOVZX):
					if insn.address not in info.gv_map:
						info.gv_list.append([insn.address, gv_addr_0, 2])
						info.gv_map[insn.address] = [[gv_addr_0, 2]]
						if gv_addr_0 not in info.gv_reverse_map:
							info.gv_reverse_map[gv_addr_0] = [[insn.address, 2]]
						else:
							info.gv_reverse_map[gv_addr_0].append([insn.address, 2])
				else:
					if insn.address not in info.gv_map:
						info.gv_list.append([insn.address, gv_addr_0, 3])
						info.gv_map[insn.address] = [[gv_addr_0, 3]]
						if gv_addr_0 not in info.gv_reverse_map:
							info.gv_reverse_map[gv_addr_0] = [[insn.address, 3]]
						else:
							info.gv_reverse_map[gv_addr_0].append([insn.address, 3])
			elif op_access_1 == 1:
				if insn.address not in info.gv_map:
					info.gv_list.append([insn.address, gv_addr_1, 1])
					info.gv_map[insn.address] = [[gv_addr_1, 1]]
					if gv_addr_1 not in info.gv_reverse_map:
						info.gv_reverse_map[gv_addr_1] = [[insn.address, 1]]
					else:
						info.gv_reverse_map[gv_addr_1].append([insn.address, 1])


	#for gv in info.gv_list:
	#	print("*")
	#	print(info.insnsmap[gv[0]].mnemonic)
	#	print(hex(gv[0]))
	#	print(hex(gv[1]))
	#	print(str(gv[2]))

	#for addr in sorted(info.gv_map):
	#	print("*")
	#	print(info.insnsmap[addr].mnemonic)
	#	print(hex(addr))
	#	print(hex(info.gv_map[addr][0][0]))
	#	print(str(info.gv_map[addr][0][1]))

	#for gv_addr in sorted(info.gv_reverse_map):
	#	print("*")
	#	print(hex(gv_addr))
	#	print("[", end='')
	#	for l in info.gv_reverse_map[gv_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")


def global_variable_analysis_2_inner(func):

	#print("global_variable_analysis_2_inner")
	#print("hex(func[0]): " + hex(func[0]))
	#for gv_addr in sorted(info.track_cells):
	#	print("hex(gv_addr): " + hex(gv_addr))
	

	# for debugging
	#print("visitmap:")
	visitmap = {}
	for addr in info.insnaddrs:
		if addr >= func[0] and addr <= func[2]:
			visitmap[addr] = 0
			#print(hex(addr))

	resolve_start = func[0]
	info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

	makeregistersymbolic("init_")
	#info.state.regs.rsp = initial_rsp = info.state.solver.BVS("rsp", 64)
	#info.state.regs.rbp = info.state.solver.BVS("rbp", 64)
	initial_rsp = info.state.solver.eval(info.state.regs.rsp)
	initial_rbp = info.state.solver.eval(info.state.regs.rbp)

	#print(hex(initial_rsp))
	#print(hex(initial_rbp))
	#print(initial_rsp.__class__)
	#print(initial_rbp.__class__)

	# generate a fixed pointer for each tracked gv
	if info.init_track_cells_at_beginning == True:
		for gv_addr in sorted(info.track_cells):
			#gen_hv_pointer = gv_addr + 0x7fffff000000000
			gen_hv_pointer = gv_addr + initial_rsp + 0xff00000000
			hv_content = info.state.solver.BVS("hv_content_" + hex(gv_addr), 64)
			info.state.memory.store(gv_addr, gen_hv_pointer, 8, endness=archinfo.Endness.LE)
			info.state.memory.store(gen_hv_pointer, hv_content, 8, endness=archinfo.Endness.LE)
			print("info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))
			#print("info.state.memory.load(gen_hv_pointer, 8): " + str(info.state.memory.load(gen_hv_pointer, 8, endness=archinfo.Endness.LE)))

	info.states = [info.state]
	loop_times = 0

	while True:
		if not info.states:
			break

		info.state = info.states.pop(0)

		if info.state.addr < func[0] or info.state.addr > func[2]:
			continue

		#print(hex(info.state.addr))
		#print(len(info.states))

		visitmap[info.state.addr] = 1




		if info.state.addr not in info.insnsmap:
			continue

		insn = info.insnsmap[info.state.addr]



		if insn.id == X86_INS_RET or insn.id == X86_INS_RETF or insn.id == X86_INS_RETFQ:
			#if info.state.regs.rax.symbolic:
			#	print(info.state.regs.rax)
			continue

		if info.state.addr in info.backedgemap:
		#	print("info.loop_times_map[" + hex(info.state.addr) + "]: " + str(info.loop_times_map[info.state.addr]))
		#	if info.loop_times_map[info.state.addr] <= info.MAX_SINGLE_ITERATE: 
		#		info.loop_times_map[info.state.addr] = info.loop_times_map[info.state.addr] + 1
		#	if info.loop_times_map[info.state.addr] > info.MAX_SINGLE_ITERATE:
		#		continue
			print("loop_times: " + str(loop_times))
			if loop_times <= info.MAX_ITERATE:
				loop_times = loop_times + 1
			else:
				continue


		#if info.loop_times_map[info.state.addr] <= info.MAX_SINGLE_ITERATE: 
		#	info.loop_times_map[info.state.addr] = info.loop_times_map[info.state.addr] + 1
		#else:
		#	continue

		if not info.state.addr in info.loop_times_map:
			info.loop_times_map[info.state.addr] = 0
		elif info.loop_times_map[info.state.addr] <= info.MAX_SINGLE_ITERATE: 
			info.loop_times_map[info.state.addr] = info.loop_times_map[info.state.addr] + 1
		else:
			continue


		#if info.state.addr >= 0x40898f and info.state.addr <= 0x4089a5:
		#	print("info.state.addr: " + hex(info.state.addr))
		#	print("info.state.regs.rax: " + str(info.state.regs.rax))

		#if info.state.addr == 0x4089a9:
		#	print("info.state.addr: " + hex(info.state.addr))
		#	print("info.state.regs.rax: " + str(info.state.regs.rax))
		#	exit(0)


		if insn.id == X86_INS_CALL and findnextinsaddr(info.state.addr) != -0x1 and findnextinsaddr(info.state.addr) < func[2]:
			rsp = info.state.regs.rsp
			rbp = info.state.regs.rbp

			gv_value_map = {}

			# get tracked cells
			for gv_addr in sorted(info.track_cells):
				gv_value_map[gv_addr] = info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)
				#print("before call site: info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))

			info.state = info.project.factory.entry_state(addr=info.state.addr, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
			info.state.regs.rsp = rsp
			info.state.regs.rbp = rbp
			#
			info.state.memory.store(0x79e960, 64, 8, endness=archinfo.Endness.LE)
			makeregistersymbolic("sym_" + hex(info.state.addr) + "_")

			# malloc
			if info.callinsnmap[info.state.addr] in info.mallocfunctionaddrs:
				#print(hex(info.state.addr))
				info.state.regs.rax = info.state.solver.BVS("heap_var_" + hex(info.state.addr), 64)
				#print(info.state.regs.rax)

				#if func[0] in info.heap_init_funcs and info.state.addr in info.hvtogv_map:
					#info.state.regs.rax = info.state.solver.BVS("heap_var_" + hex(info.state.addr), 64)
				#	gen_hv_pointer = info.state.addr + initial_rsp + 0xff00000000
				#	hv_content = info.state.solver.BVS("hv_content_" + hex(info.state.addr), 64)
				#	info.state.registers.store("rax", gen_hv_pointer)
					#info.state.memory.store(gv_addr, gen_hv_pointer, 8, endness=archinfo.Endness.LE)
				#	info.state.memory.store(gen_hv_pointer, hv_content, 8, endness=archinfo.Endness.LE)
				#	print("info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))
					#print("info.state.memory.load(gen_hv_pointer, 8): " + str(info.state.memory.load(gen_hv_pointer, 8, endness=archinfo.Endness.LE)))
				#	print("reg rax value after malloc: " + str(info.state.registers.load("rax")))




			info.state.regs.rip = findnextinsaddr(info.state.addr)


			# maintain tracked cells
			for gv_addr in sorted(info.track_cells):
				info.state.memory.store(gv_addr, gv_value_map[gv_addr], 8, endness=archinfo.Endness.LE)
				#print("after call site: info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))

			info.states.append(info.state)
			#print("call fall through: ")
			#print("info.state.regs.rip: " + hex(info.state.solver.eval(info.state.regs.rip)))
			#print("info.state.addr: " + hex(info.state.addr))
			continue



		#if info.state.addr == 0x408993:
		#	print("0x408993 rax: " + str(info.state.registers.load("rax")))


		#print("++")
		#print("info.states:")
		#for state in info.states:
		#	print(hex(state.addr))
		#print("++")


		# 1-operand insn
		resolved_mem_addr = 0

		if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.segment == 0:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[0].value.mem.base >= X86_REG_AH and insn.operands[0].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[0].value.mem.base == X86_REG_RIP:
						if findnextinsaddr(base) != -0x1:
							base = findnextinsaddr(base)
							base_concrete = 1
						else:
							base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[0].value.mem.index >= X86_REG_AH and insn.operands[0].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[0].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[0].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[0].value.mem.scale
				disp = insn.operands[0].value.mem.disp
				resolved_mem_addr = base + index * scale + disp
				#print(insn.reg_name(insn.operands[0].value.mem.base))
				#print(hex(base))
				print("resolved_mem_addr: " + hex(resolved_mem_addr))

				# not stack variable and not heap variable
				if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
					and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
				#if resolved_mem_addr > initial_rsp + 0x100000000 or resolved_mem_addr < initial_rsp - 0x100000000:
					if info.state.addr not in info.gv_map:
						if insn.id == X86_INS_INC:
							info.gv_list.append([info.state.addr, resolved_mem_addr, 3])
							info.gv_map[info.state.addr] = [[resolved_mem_addr, 3]]
							if resolved_mem_addr not in info.gv_reverse_map:
								info.gv_reverse_map[resolved_mem_addr] = [[info.state.addr, 3]]
							else:
								info.gv_reverse_map[resolved_mem_addr].append([info.state.addr, 3])
						else:
							info.gv_list.append([info.state.addr, resolved_mem_addr, 1])
							info.gv_map[info.state.addr] = [[resolved_mem_addr, 1]]
							if resolved_mem_addr not in info.gv_reverse_map:
								info.gv_reverse_map[resolved_mem_addr] = [[info.state.addr, 1]]
							else:
								info.gv_reverse_map[resolved_mem_addr].append([info.state.addr, 1])

				# heap variable
				if resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000:
					# check the dereferenced value to see if it is heap variable content
					print("info.state.memory.load(resolved_mem_addr, 8): " + str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)))
					if "hv_content" in str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)):
						s1 = str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE))
						s2 = s1[s1.index("hv_content") + 11:]
						s3 = s2[:s2.index("_")]
						gv_addr = int(s3, 16)
						print("hv_content")
						print(hex(gv_addr))
						if gv_addr in info.gvtohv_map:
							for heap_var_init_insn_addr in info.gvtohv_map[gv_addr]:
								if info.state.addr not in info.gv_map:
									if insn.id == X86_INS_INC:
										info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 3])
										info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 3]]
										if heap_var_init_insn_addr not in info.gv_reverse_map:
											info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 3]]
										else:
											info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 3])
									else:
										info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 1])
										info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 1]]
										if heap_var_init_insn_addr not in info.gv_reverse_map:
											info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 1]]
										else:
											info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 1])

		# 2-operand insn
		resolved_mem_addr = 0
		source_resolved = 0
		dist_resolved = 0
		source_addr = 0
		dist_addr = 0
		gv_holding_hv = 0

		# 2-operand insn, examine source operand
		if len(insn.operands) == 2 and insn.operands[1].type == X86_OP_MEM and insn.id != X86_INS_LEA and insn.operands[1].value.mem.segment == 0:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[1].value.mem.base >= X86_REG_AH and insn.operands[1].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[1].value.mem.base == X86_REG_RIP:
						if findnextinsaddr(base) != -0x1:
							base = findnextinsaddr(base)
							base_concrete = 1
						else:
							base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[1].value.mem.index >= X86_REG_AH and insn.operands[1].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[1].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[1].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[1].value.mem.scale
				disp = insn.operands[1].value.mem.disp
				resolved_mem_addr = base + index * scale + disp

				# not stack variable and not heap variable
				if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
					and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
					print("resolved_mem_addr: " + hex(resolved_mem_addr))

					source_resolved = 1
					source_addr = resolved_mem_addr

				# heap variable
				if resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000:

					print("resolved_mem_addr: " + hex(resolved_mem_addr))
					source_resolved = 1
					source_addr = resolved_mem_addr

					# check the dereferenced value to see if it is heap variable content
					print("info.state.memory.load(resolved_mem_addr, 8): " + str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)))
					if "hv_content" in str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)):
						s1 = str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE))
						s2 = s1[s1.index("hv_content") + 11:]
						s3 = s2[:s2.index("_")]
						gv_addr = int(s3, 16)
						print("hv_content")
						print(hex(gv_addr))
						gv_holding_hv = gv_addr

		# 2-oprand insn, examine dist operand
		if len(insn.operands) == 2 and insn.operands[0].type == X86_OP_MEM and insn.id != X86_INS_LEA and insn.operands[0].value.mem.segment == 0:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[0].value.mem.base >= X86_REG_AH and insn.operands[0].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[0].value.mem.base == X86_REG_RIP:
						if findnextinsaddr(base) != -0x1:
							base = findnextinsaddr(base)
							base_concrete = 1
						else:
							base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[0].value.mem.index >= X86_REG_AH and insn.operands[0].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[0].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[0].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[0].value.mem.scale
				disp = insn.operands[0].value.mem.disp
				resolved_mem_addr = base + index * scale + disp

				# not stack variable and not heap variable
				if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
					and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):

					print("resolved_mem_addr: " + hex(resolved_mem_addr))

					dist_resolved = 1
					dist_addr = resolved_mem_addr

					if insn.operands[1].type == X86_OP_REG and insn.operands[1].value.reg >= X86_REG_AH and insn.operands[1].value.reg <= X86_REG_RSP:
						#print(hex(insn.address))
						#print("insn.reg_name(insn.operands[1].value.reg): " + insn.reg_name(insn.operands[1].value.reg))
						#print(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg)))
						#print(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg)).symbolic)
						#print("rbp: " + hex(info.state.solver.eval(info.state.regs.rbp)))
						#print("[rbp - 0x10]: " + str(info.state.memory.load(info.state.solver.eval(info.state.regs.rbp) - 0x10, 8, endness=archinfo.Endness.LE)))

						if info.state.registers.load(insn.reg_name(insn.operands[1].value.reg)).symbolic:
							try:
								s1 = str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg)))
							except:
								s1 = ""
							if "heap_var_" in s1:
								s2 = s1[s1.index("heap_var_") + 9:]
								#print("s2: " + s2)
								s3 = s2[:s2.index("_")]
								#print("s3: " + s3)
								heap_var_init_insn_addr = int(s3, 16)
								#print("heap_var_init_insn_addr: " + hex(heap_var_init_insn_addr))
								gv_addr = resolved_mem_addr
								if gv_addr not in info.gvtohv_map:
									info.gvtohv_map[gv_addr] = [heap_var_init_insn_addr]
								elif heap_var_init_insn_addr not in info.gvtohv_map[gv_addr]:
									info.gvtohv_map[gv_addr].append(heap_var_init_insn_addr)

								if heap_var_init_insn_addr not in info.hvtogv_map:
									info.hvtogv_map[heap_var_init_insn_addr] = [gv_addr]
								elif heap_var_init_insn_addr in info.hvtogv_map:
									info.hvtogv_map[heap_var_init_insn_addr].append(gv_addr)

								'''
								if gv_addr in info.track_cells:
									gen_hv_pointer = gv_addr + initial_rsp + 0xff00000000
									hv_content = info.state.solver.BVS("hv_content_" + hex(gv_addr), 64)
									info.state.registers.store(insn.reg_name(insn.operands[1].value.reg), gen_hv_pointer)
									#info.state.memory.store(gv_addr, gen_hv_pointer, 8, endness=archinfo.Endness.LE)
									info.state.memory.store(gen_hv_pointer, hv_content, 8, endness=archinfo.Endness.LE)
									print("info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))
									#print("info.state.memory.load(gen_hv_pointer, 8): " + str(info.state.memory.load(gen_hv_pointer, 8, endness=archinfo.Endness.LE)))
									print("reg value after malloc: " + str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg))))
								'''
								if func[0] in info.heap_init_funcs:
									gen_hv_pointer = heap_var_init_insn_addr + initial_rsp + 0xff00000000
									hv_content = info.state.solver.BVS("hv_content_" + hex(heap_var_init_insn_addr), 64)
									info.state.registers.store(insn.reg_name(insn.operands[1].value.reg), gen_hv_pointer)
									info.state.memory.store(gen_hv_pointer, hv_content, 8, endness=archinfo.Endness.LE)
									print("info.state.memory.load(gv_addr, 8): " + str(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))
									#print("info.state.memory.load(gen_hv_pointer, 8): " + str(info.state.memory.load(gen_hv_pointer, 8, endness=archinfo.Endness.LE)))
									print("reg rax value after becoming shared: " + str(info.state.registers.load("rax")))

						#if insn.address == 0x4089a9:
						#	pass

				# heap variable
				if resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000:

					print("resolved_mem_addr: " + hex(resolved_mem_addr))
					dist_resolved = 1
					dist_addr = resolved_mem_addr

					# check the dereferenced value to see if it is heap variable content
					print("info.state.memory.load(resolved_mem_addr, 8): " + str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)))
					if "hv_content" in str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE)):
						s1 = str(info.state.memory.load(resolved_mem_addr, 8, endness=archinfo.Endness.LE))
						s2 = s1[s1.index("hv_content") + 11:]
						s3 = s2[:s2.index("_")]
						gv_addr = int(s3, 16)
						print("write")
						print("hv_content")
						print("gv_addr: " + hex(gv_addr))
						gv_holding_hv = gv_addr


		# not stack variable and not heap variable
		if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
			and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
			if info.state.addr not in info.gv_map:
				if dist_resolved == 1:
					if (insn.id >= X86_INS_CMP and insn.id <= X86_INS_CMPXCHG8B) or insn.id == X86_INS_TEST:
						info.gv_list.append([info.state.addr, dist_addr, 1])
						info.gv_map[info.state.addr] = [[dist_addr, 1]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 1]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 1])
					elif insn.id == X86_INS_MOVAPD or insn.id == X86_INS_MOVAPS or (insn.id >= X86_INS_MOVD and insn.id <= X86_INS_MOVQ) \
						 or (insn.id >= X86_INS_MOV and insn.id <= X86_INS_MOVZX):
						info.gv_list.append([info.state.addr, dist_addr, 2])
						info.gv_map[info.state.addr] = [[dist_addr, 2]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 2]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 2])
					else:
						info.gv_list.append([info.state.addr, dist_addr, 3])
						info.gv_map[info.state.addr] = [[dist_addr, 3]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 3]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 3])

				elif source_resolved == 1:
					info.gv_list.append([info.state.addr, source_addr, 1])
					info.gv_map[info.state.addr] = [[source_addr, 1]]
					if source_addr not in info.gv_reverse_map:
						info.gv_reverse_map[source_addr] = [[info.state.addr, 1]]
					else:
						info.gv_reverse_map[source_addr].append([info.state.addr, 1])

		# heap variable
		if resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000:
			if info.state.addr not in info.gv_map and gv_holding_hv != 0:
				print("tititi")
				print("gv_holding_hv: " + hex(gv_holding_hv))
				# if gv_holding_hv is actually a hv init insn addr
				if gv_holding_hv >= info.insnaddrs[0] and gv_holding_hv <= info.insnaddrs[-1]:
					pass
					if dist_resolved == 1:
						if (insn.id >= X86_INS_CMP and insn.id <= X86_INS_CMPXCHG8B) or insn.id == X86_INS_TEST:
							info.gv_list.append([info.state.addr, gv_holding_hv, 1])
							if gv_holding_hv not in info.gv_reverse_map:
								info.gv_map[info.state.addr] = [[gv_holding_hv, 1]]
								info.gv_reverse_map[gv_holding_hv] = [[info.state.addr, 1]]
							else:
								if info.state.addr not in info.gv_map:
									info.gv_map[info.state.addr] = []
								info.gv_map[info.state.addr].append([gv_holding_hv, 1])
								info.gv_reverse_map[gv_holding_hv].append([info.state.addr, 1])
						elif insn.id == X86_INS_MOVAPD or insn.id == X86_INS_MOVAPS or (insn.id >= X86_INS_MOVD and insn.id <= X86_INS_MOVQ) \
							 or (insn.id >= X86_INS_MOV and insn.id <= X86_INS_MOVZX):
							info.gv_list.append([info.state.addr, gv_holding_hv, 2])
							if gv_holding_hv not in info.gv_reverse_map:
								#print("dododo")
								#print("gv_holding_hv: " + hex(gv_holding_hv))
								info.gv_map[info.state.addr] = [[gv_holding_hv, 2]]
								info.gv_reverse_map[gv_holding_hv] = [[info.state.addr, 2]]
							else:
								if info.state.addr not in info.gv_map:
									info.gv_map[info.state.addr] = []
								info.gv_map[info.state.addr].append([gv_holding_hv, 2])
								info.gv_reverse_map[gv_holding_hv].append([info.state.addr, 2])
						else:
							info.gv_list.append([info.state.addr, gv_holding_hv, 3])
							if gv_holding_hv not in info.gv_reverse_map:
								info.gv_map[info.state.addr] = [[gv_holding_hv, 3]]
								info.gv_reverse_map[gv_holding_hv] = [[info.state.addr, 3]]
							else:
								if info.state.addr not in info.gv_map:
									info.gv_map[info.state.addr] = []
								info.gv_map[info.state.addr].append([gv_holding_hv, 3])
								info.gv_reverse_map[gv_holding_hv].append([info.state.addr, 3])

					elif source_resolved == 1:
							info.gv_list.append([info.state.addr, gv_holding_hv, 1])
							if gv_holding_hv not in info.gv_reverse_map:
								info.gv_map[info.state.addr] = [[gv_holding_hv, 1]]
								info.gv_reverse_map[gv_holding_hv] = [[info.state.addr, 1]]
							else:
								if info.state.addr not in info.gv_map:
									info.gv_map[info.state.addr] = []
								info.gv_map[info.state.addr].append([gv_holding_hv, 1])
								info.gv_reverse_map[gv_holding_hv].append([info.state.addr, 1])
				else:
					#print("yayaya")
					for heap_var_init_insn_addr in info.gvtohv_map[gv_holding_hv]:
						#print(hex(heap_var_init_insn_addr))
						if dist_resolved == 1:
							if (insn.id >= X86_INS_CMP and insn.id <= X86_INS_CMPXCHG8B) or insn.id == X86_INS_TEST:
								info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 1])
								if heap_var_init_insn_addr not in info.gv_reverse_map:
									info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 1]]
									info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 1]]
								else:
									if info.state.addr not in info.gv_map:
										info.gv_map[info.state.addr] = []
									info.gv_map[info.state.addr].append([heap_var_init_insn_addr, 1])
									info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 1])
							elif insn.id == X86_INS_MOVAPD or insn.id == X86_INS_MOVAPS or (insn.id >= X86_INS_MOVD and insn.id <= X86_INS_MOVQ) \
								 or (insn.id >= X86_INS_MOV and insn.id <= X86_INS_MOVZX):
								info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 2])
								if heap_var_init_insn_addr not in info.gv_reverse_map:
									info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 2]]
									info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 2]]
								else:
									if info.state.addr not in info.gv_map:
										info.gv_map[info.state.addr] = []
									info.gv_map[info.state.addr].append([heap_var_init_insn_addr, 2])
									info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 2])
							else:
								info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 3])
								if heap_var_init_insn_addr not in info.gv_reverse_map:
									info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 3]]
									info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 3]]
								else:
									if info.state.addr not in info.gv_map:
										info.gv_map[info.state.addr] = []
									info.gv_map[info.state.addr].append([heap_var_init_insn_addr, 3])
									info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 3])

						elif source_resolved == 1:
								info.gv_list.append([info.state.addr, heap_var_init_insn_addr, 1])
								if heap_var_init_insn_addr not in info.gv_reverse_map:
									info.gv_map[info.state.addr] = [[heap_var_init_insn_addr, 1]]
									info.gv_reverse_map[heap_var_init_insn_addr] = [[info.state.addr, 1]]
								else:
									if info.state.addr not in info.gv_map:
										info.gv_map[info.state.addr] = []
									info.gv_map[info.state.addr].append([heap_var_init_insn_addr, 1])
									info.gv_reverse_map[heap_var_init_insn_addr].append([info.state.addr, 1])



		info.succs = []
		try:
			#skip = 0
			#print("+")
			info.succs = info.project.factory.successors(info.state, num_inst=1).successors
		except:
			pass


		#print("+")
		#print(hex(info.state.addr) + "succs: ")

		for succ in info.succs:
			#print(hex(succ.addr))
			if not succ.regs.rip.symbolic:
				#print("++")
				info.states.append(succ)
		#print("+")

		#for succ in info.project.factory.successors(info.state, num_inst=1).unsat_successors:
		#	if not succ.regs.rip.symbolic:
		#		print("unsat_successors: " + hex(succ.addr))

		#if info.state.addr == 0x408978:
		#	exit(0)


		gc.collect()


	for addr in info.insnaddrs:
		info.loop_times_map[addr] = 0

	gc.collect()



	'''
	unvisited = []
	#print("unvisited: ")
	for addr in visitmap:
		if visitmap[addr] == 0:
			#print(hex(addr))
			unvisited.append(addr)

	if len(unvisited) != 0:

		print("unvisited: ")
		for addr in sorted(visitmap):
			if visitmap[addr] == 0:
				print(hex(addr))

		info.outputfile = open(os.path.realpath(info.args.output), "a") 
		info.outputfile.write("unvisited:\n")
		info.outputfile.write("[")
		for addr in sorted(visitmap):
			if visitmap[addr] == 0:
				info.outputfile.write(hex(addr) + " ")
		info.outputfile.write("]\n")
		info.outputfile.close()
	'''

	#for gv_addr in sorted(info.gv_reverse_map):
	#	print("*")
	#	print(hex(gv_addr))
	#	print("[", end='')
	#	for l in info.gv_reverse_map[gv_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")


	#for gv_addr in sorted(info.gvtohv_map):
	#	print("*")
	#	print("gv_addr: " + hex(gv_addr))
	#	print("[", end='')
	#	for heap_var_init_insn_addr in info.gvtohv_map[gv_addr]:
	#		print(hex(heap_var_init_insn_addr) + " ", end='')
	#	print("]")


def global_variable_analysis_2():
	# for each function, do localized VSA (path sensitive)

	# first set a limit for loops
	info.MAX_ITERATE = 10
	info.MAX_SINGLE_ITERATE = 2

	info.loop_times_map = {}

	#for addr in sorted(info.backedgemap):
		#print(hex(addr))
	#	info.loop_times_map[addr] = 0

	for addr in info.insnaddrs:
		info.loop_times_map[addr] = 0

	#once = 0
	for func in info.func_list:
		if func[0] not in info.whitelist:# and func[0] == 0x52f010:
			#if once == 1:
			#	break
			#if func[1] != "_ZL11do_save_tcsPv":
			#	continue
			#once = 1

			if info.args.app == True and func[0] in info.intel_sgx_sdk_func_insn_addrs:
				continue

			#print("*")
			#print(hex(func[0]))
			#print(func[1])
			#print(hex(func[2]))
		
			resolve_start = func[0]

			global_variable_analysis_2_inner(func)


	#for gv_addr in sorted(info.gv_reverse_map):
	#	print("*")
	#	print(hex(gv_addr))
	#	print("[", end='')
	#	for l in info.gv_reverse_map[gv_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")

	#for gv_addr in sorted(info.gvtohv_map):
	#	print("*")
	#	print("gv_addr: " + hex(gv_addr))
	#	print("[", end='')
	#	for heap_var_init_insn_addr in info.gvtohv_map[gv_addr]:
	#		print(hex(heap_var_init_insn_addr) + " ", end='')
	#	print("]")

	# from shared heap variable pointer, get where it is read or write
	for gv_addr in sorted(info.gvtohv_map):
		if gv_addr in info.gv_reverse_map:
			for l in info.gv_reverse_map[gv_addr]:
				if l[1] == 1 or l[1] == 3:
					if get_enclosing_func_addr(l[0]) != -0x1:
						info.heap_pointer_access_func_addrs.add(get_enclosing_func_addr(l[0]))
						if get_enclosing_func_addr(l[0]) not in info.heap_pointer_access_func_addr_to_gv_map:
							info.heap_pointer_access_func_addr_to_gv_map[get_enclosing_func_addr(l[0])] = set()
						info.heap_pointer_access_func_addr_to_gv_map[get_enclosing_func_addr(l[0])].add(gv_addr)
						for heap_var_init_insn_addr in sorted(info.gvtohv_map[gv_addr]):
							if l[0] not in info.heap_pointer_access_insn_map:
								info.heap_pointer_access_insn_map[l[0]] = [[heap_var_init_insn_addr, l[1]]]
							else:
								info.heap_pointer_access_insn_map[l[0]].append([heap_var_init_insn_addr, l[1]])

	#for func_addr in sorted(info.heap_pointer_access_func_addrs):
	#	print("*")
	#	print("func_addr: " + hex(func_addr))

	#for access_addr in sorted(info.heap_pointer_access_insn_map):
	#	print("*")
	#	print("access_addr: " + hex(access_addr))
	#	print("[", end='')
	#	for l in info.heap_pointer_access_insn_map[access_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")

	#for func_addr in sorted(info.heap_pointer_access_func_addr_to_gv_map):
	#	print("*")
	#	print("func_addr: " + hex(func_addr))
	#	print("[", end='')
	#	for gv_addr in sorted(info.heap_pointer_access_func_addr_to_gv_map[func_addr]):
	#		print(hex(gv_addr) + " ", end='')
	#	print("]")

	for heap_var_init_insn_addr in sorted(info.hvtogv_map):
		if get_enclosing_func_addr(heap_var_init_insn_addr) != -0x1:
			info.heap_init_funcs.add(get_enclosing_func_addr(heap_var_init_insn_addr))

	for heap_init_func in sorted(info.heap_init_funcs):
		print("hex(heap_init_func): " + hex(heap_init_func))

	#track_cells
	for func in info.func_list:
		if func[0] not in info.whitelist:
			#print("*")
			#print(hex(func[0]))
			#print(func[1])
			if info.args.app == True and func[0] in info.intel_sgx_sdk_func_insn_addrs:
				continue

			if func[0] in info.heap_pointer_access_func_addr_to_gv_map or func[0] in info.heap_init_funcs:

				if func[0] in info.heap_pointer_access_func_addr_to_gv_map:
					info.track_cells = info.track_cells.union(info.heap_pointer_access_func_addr_to_gv_map[func[0]])

				if func[0] in info.heap_init_funcs:
					for hv in sorted(info.hvtogv_map):
						if hv >= func[0] and hv <= func[2]:
							#print("nanana" + hex(hv))
							#print("info.hvtogv_map[hv]:")
							#for gv in sorted(info.hvtogv_map[hv]):
							#	print(hex(gv))
							#print("info.hvtogv_map[hv] end")

							info.track_cells = info.track_cells.union(set(info.hvtogv_map[hv]))


				#print("info.track_cells: ")
				#print("[", end='')
				#for gv_addr in sorted(info.track_cells):
				#	print(hex(gv_addr) + " ", end='')
				#print("]")


				if func[0] in info.heap_pointer_access_func_addr_to_gv_map:
					info.init_track_cells_at_beginning = True

				global_variable_analysis_2_inner(func)

				info.track_cells = set()
				info.init_track_cells_at_beginning = False


def global_variable_analysis_2_inner_fast(bb_start, bb_end):

	visitmap = {}
	addr = bb_start
	while addr <= bb_end and addr != -1:
		visitmap[addr] = 0
		addr = findnextinsaddr(addr)

	info.state = info.project.factory.entry_state(addr=bb_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

	makeregistersymbolic("init_")
	initial_rsp = info.state.solver.eval(info.state.regs.rsp)
	initial_rbp = info.state.solver.eval(info.state.regs.rbp)

	info.states = [info.state]

	while True:
		if not info.states:
			break

		info.state = info.states.pop(0)

		if info.state.addr < bb_start or info.state.addr > bb_end:
			break

		if not info.state.addr in visitmap or visitmap[info.state.addr] != 0:
			break

		if info.args.output2:
			print(hex(info.state.addr))
		##print(hex(info.state.addr))

		#print(len(info.states))

		if info.state.addr not in info.insnsmap:
			break

		insn = info.insnsmap[info.state.addr]

		resolved_mem_addr = 0

		# 1-operand insn
		if len(insn.operands) == 1 and insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.segment == 0 and insn.operands[0].value.mem.base != X86_REG_RIP \
			 and insn.operands[0].value.mem.base != X86_REG_RBP:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[0].value.mem.base >= X86_REG_AH and insn.operands[0].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[0].value.mem.base == X86_REG_RIP:
						base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[0].value.mem.index >= X86_REG_AH and insn.operands[0].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[0].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[0].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[0].value.mem.scale
				disp = insn.operands[0].value.mem.disp
				resolved_mem_addr = base + index * scale + disp
				#print(insn.reg_name(insn.operands[0].value.mem.base))
				#print(hex(base))

				print("resolved_mem_addr: " + hex(resolved_mem_addr))
				#print("initial_rsp1: " + hex(initial_rsp))
				#print(v_dyn_addr_in_data_sections(resolved_mem_addr))

				# not stack variable and not heap variable
				#if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
				#	and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
				if v_dyn_addr_in_data_sections(resolved_mem_addr) == True:
					if info.state.addr not in info.gv_map:
						if insn.id == X86_INS_INC:
							info.gv_list.append([info.state.addr, resolved_mem_addr, 3])
							info.gv_map[info.state.addr] = [[resolved_mem_addr, 3]]
							if resolved_mem_addr not in info.gv_reverse_map:
								info.gv_reverse_map[resolved_mem_addr] = [[info.state.addr, 3]]
							else:
								info.gv_reverse_map[resolved_mem_addr].append([info.state.addr, 3])
						else:
							info.gv_list.append([info.state.addr, resolved_mem_addr, 1])
							info.gv_map[info.state.addr] = [[resolved_mem_addr, 1]]
							if resolved_mem_addr not in info.gv_reverse_map:
								info.gv_reverse_map[resolved_mem_addr] = [[info.state.addr, 1]]
							else:
								info.gv_reverse_map[resolved_mem_addr].append([info.state.addr, 1])

		# 2-operand insn
		resolved_mem_addr = 0
		source_resolved = 0
		dist_resolved = 0
		source_addr = 0
		dist_addr = 0

		# 2-operand insn, examine source operand
		if len(insn.operands) == 2 and insn.operands[1].type == X86_OP_MEM and insn.id != X86_INS_LEA and insn.operands[1].value.mem.segment == 0 \
			and insn.operands[1].value.mem.base != X86_REG_RIP \
			and insn.operands[1].value.mem.base != X86_REG_RBP:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[1].value.mem.base >= X86_REG_AH and insn.operands[1].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[1].value.mem.base == X86_REG_RIP:
						base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[1].value.mem.index >= X86_REG_AH and insn.operands[1].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[1].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[1].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[1].value.mem.scale
				disp = insn.operands[1].value.mem.disp
				resolved_mem_addr = base + index * scale + disp

				# not stack variable and not heap variable
				#if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
				#	and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
				if v_dyn_addr_in_data_sections(resolved_mem_addr) == True:
					print("resolved_mem_addr: " + hex(resolved_mem_addr))
					#print("initial_rsp2: " + hex(initial_rsp))
					#print(v_dyn_addr_in_data_sections(resolved_mem_addr))

					source_resolved = 1
					source_addr = resolved_mem_addr


		# 2-oprand insn, examine dist operand
		if len(insn.operands) == 2 and insn.operands[0].type == X86_OP_MEM and insn.id != X86_INS_LEA and insn.operands[0].value.mem.segment == 0 \
			and insn.operands[0].value.mem.base != X86_REG_RIP \
			and insn.operands[0].value.mem.base != X86_REG_RBP:
			base = 0
			index = 0
			scale = 0
			disp = 0
			base_concrete = 0
			index_concrete = 0

			if insn.operands[0].value.mem.base >= X86_REG_AH and insn.operands[0].value.mem.base <= X86_REG_RSP:
				base_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base))
				if not base_reg_value.symbolic:
					base = info.state.solver.eval(base_reg_value)
					if insn.operands[0].value.mem.base == X86_REG_RIP:
						base_concrete = 0
					else:
						base_concrete = 1

			if insn.operands[0].value.mem.index >= X86_REG_AH and insn.operands[0].value.mem.index <= X86_REG_RSP:
				index_reg_value = info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index))
				if not index_reg_value.symbolic:
					index = info.state.solver.eval(index_reg_value)
					index_concrete = 1

			if insn.operands[0].value.mem.base == 0:
				base_concrete = 1
			if insn.operands[0].value.mem.index == 0:
				index_concrete = 1

			if base_concrete == 1 and index_concrete == 1:
				scale = insn.operands[0].value.mem.scale
				disp = insn.operands[0].value.mem.disp
				resolved_mem_addr = base + index * scale + disp

				# not stack variable and not heap variable
				#if not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
				#	and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
				if v_dyn_addr_in_data_sections(resolved_mem_addr) == True:

					print("resolved_mem_addr: " + hex(resolved_mem_addr))
					#print("initial_rsp3: " + hex(initial_rsp))
					#print(v_dyn_addr_in_data_sections(resolved_mem_addr))

					dist_resolved = 1
					dist_addr = resolved_mem_addr


		# not stack variable and not heap variable
		if resolved_mem_addr != 0 and not (resolved_mem_addr >= initial_rsp - 0x100000000 and resolved_mem_addr <= initial_rsp + 0x100000000) \
			and not (resolved_mem_addr >= initial_rsp + 0xff00000000 and resolved_mem_addr <= initial_rsp + 0x10100000000):
			if info.state.addr not in info.gv_map:
				if dist_resolved == 1:
					if (insn.id >= X86_INS_CMP and insn.id <= X86_INS_CMPXCHG8B) or insn.id == X86_INS_TEST:
						info.gv_list.append([info.state.addr, dist_addr, 1])
						info.gv_map[info.state.addr] = [[dist_addr, 1]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 1]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 1])
					elif insn.id == X86_INS_MOVAPD or insn.id == X86_INS_MOVAPS or (insn.id >= X86_INS_MOVD and insn.id <= X86_INS_MOVQ) \
						 or (insn.id >= X86_INS_MOV and insn.id <= X86_INS_MOVZX):
						info.gv_list.append([info.state.addr, dist_addr, 2])
						info.gv_map[info.state.addr] = [[dist_addr, 2]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 2]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 2])
					else:
						info.gv_list.append([info.state.addr, dist_addr, 3])
						info.gv_map[info.state.addr] = [[dist_addr, 3]]
						if dist_addr not in info.gv_reverse_map:
							info.gv_reverse_map[dist_addr] = [[info.state.addr, 3]]
						else:
							info.gv_reverse_map[dist_addr].append([info.state.addr, 3])

				elif source_resolved == 1:
					info.gv_list.append([info.state.addr, source_addr, 1])
					info.gv_map[info.state.addr] = [[source_addr, 1]]
					if source_addr not in info.gv_reverse_map:
						info.gv_reverse_map[source_addr] = [[info.state.addr, 1]]
					else:
						info.gv_reverse_map[source_addr].append([info.state.addr, 1])

		visitmap[info.state.addr] = 1
		info.succs = []

		try:
			#skip = 0
			#print("+")
			info.succs = info.project.factory.successors(info.state, num_inst=1).successors
		except:
			break

		#print("+")
		#print(hex(info.state.addr) + "succs: ")

		if len(info.succs) != 1:
			break

		if not info.succs[0].regs.rip.symbolic:
			info.states.append(info.succs[0])

	gc.collect()


def global_variable_analysis_2_fast():


	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("global_variable_analysis_2_fast\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("global_variable_analysis_2_fast")

	#print("global_variable_analysis_2_fast")

	# for each function, do localized VSA (for each certain basic balock)

	# first set a limit for loops
	info.MAX_ITERATE = 10
	info.MAX_SINGLE_ITERATE = 2

	info.loop_times_map = {}

	#for addr in sorted(info.backedgemap):
		#print(hex(addr))
	#	info.loop_times_map[addr] = 0

	for addr in info.insnaddrs:
		info.loop_times_map[addr] = 0

	for func in info.func_list:
		if func[0] not in info.whitelist:# and func[0] == 0x52f010:
			#if once == 1:
			#	break
			#if func[1] != "_ZL11do_save_tcsPv":
			#	continue
			#once = 1

			if info.args.app == True and func[0] in info.intel_sgx_sdk_func_insn_addrs:
				continue

			##print("*")


			#print(hex(func[0]))
			#print(func[1])
			#print(hex(func[2]))

			# for each instruction
			addr = func[0]
			bb_start = func[0]
			bb_end = func[0]
			check_flag = False

			while addr <= func[2] and addr != -1:
				if addr in info.insnsmap:
					insn = info.insnsmap[addr]
					if len(insn.operands) == 1:
						if insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.base != X86_REG_RIP and insn.operands[0].value.mem.base != X86_REG_RBP:
							check_flag = True
					elif len(insn.operands) == 2 and insn.id != X86_INS_LEA:
						if insn.operands[0].type == X86_OP_MEM and insn.operands[0].value.mem.base != X86_REG_RIP and insn.operands[0].value.mem.base != X86_REG_RBP:
							check_flag = True
						if insn.operands[1].type == X86_OP_MEM and insn.operands[1].value.mem.base != X86_REG_RIP and insn.operands[1].value.mem.base != X86_REG_RBP:
							check_flag = True
				if addr in info.controlinsn:
					if addr == bb_start:
						pass
					# try to check
					elif check_flag == True:
						bb_end = addr
						#print(hex(bb_start))
						if bb_end - bb_start <= 0x10:
							global_variable_analysis_2_inner_fast(bb_start, bb_end)

					bb_start = findnextinsaddr(addr)
					check_flag = False

				addr = findnextinsaddr(addr)

	#for gv_addr in sorted(info.gv_reverse_map):
	#	print("*")
	#	print(hex(gv_addr))
	#	print("[", end='')
	#	for l in info.gv_reverse_map[gv_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")


def global_variable_analysis():

	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("global_variable_analysis\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("global_variable_analysis")


	#print("global_variable_analysis")
	info.gv_reverse_mapfile = info.binaryfile + "_gv_reverse_map_tmp_file"

	# if previous analysis intermediate results exist
	# use and load these results
	if os.path.exists(info.gv_reverse_mapfile):

		info.gv_reverse_map = {}

		f = open(info.gv_reverse_mapfile, "r")
		lines = f.readlines()

		gv_addr = 0
		accesses = []
		index = 0
		line_num = 0

		for line in lines:
			if "*" in line:
				if gv_addr != 0:
					#print("*")
					#print(hex(gv_addr))
					#for access in accesses:
					#	print(hex(access[0]) + " ", end='')
					#	print(hex(access[1]) + " ", end='')
					info.gv_reverse_map[gv_addr] = copy.deepcopy(accesses)
				gv_addr = 0
				accesses = []
				index = 0
			else:
				if index == 0:
					gv_addr = int(line, 16)
					#print("gv_addr: " + hex(gv_addr))
				elif index == 1:
					access = []
					accessstrs = line[line.index("[") + 1: line.index("]")].strip().split()
					for accessstr in accessstrs:
						if accessstrs.index(accessstr) % 2 == 0:
							access.append(int(accessstr, 16))
						else:
							access.append(int(accessstr, 16))
							accesses.append(copy.deepcopy(access))
							access = []
				index = index + 1

			if line_num == len(lines) - 1:
				if gv_addr != 0:
					info.gv_reverse_map[gv_addr] = copy.deepcopy(accesses)
					gv_addr = 0
					accesses = []
					index = 0

			line_num = line_num + 1

		f.close()

		#info.outputfile = open(os.path.realpath(info.args.output), "w") 
		#for gv_addr in sorted(info.gv_reverse_map):
		#	info.outputfile.write("*\n")
		#	info.outputfile.write(hex(gv_addr) + "\n")
		#	info.outputfile.write("[")
		#	for l in info.gv_reverse_map[gv_addr]:
		#		info.outputfile.write(hex(l[0]) + " ")
		#		info.outputfile.write(hex(l[1]) + " ")
		#	info.outputfile.write("]\n")
		#info.outputfile.close()

		#for gv_addr in sorted(info.gv_reverse_map):
		#	print("*\n")
		#	print(hex(gv_addr))
		#	print("[")
		#	for l in info.gv_reverse_map[gv_addr]:
		#		print(hex(l[0]) + " ", end='')
		#		print(hex(l[1]) + " ", end='')
		#	print("]")

		return


	global_variable_analysis_1()

	if info.args.fast == False:
		global_variable_analysis_2()
	else:
		global_variable_analysis_2_fast()


	info.outputfile = open(info.gv_reverse_mapfile, "w") 
	for gv_addr in sorted(info.gv_reverse_map):
		info.outputfile.write("*\n")
		info.outputfile.write(hex(gv_addr) + "\n")
		info.outputfile.write("[")
		for l in info.gv_reverse_map[gv_addr]:
			info.outputfile.write(hex(l[0]) + " ")
			info.outputfile.write(hex(l[1]) + " ")
		info.outputfile.write("]\n")
	info.outputfile.close()




	'''
	info.outputfile = open(os.path.realpath(info.args.output), "w") 
	for gv_addr in sorted(info.gv_reverse_map):
		info.outputfile.write("*\n")
		info.outputfile.write(hex(gv_addr) + "\n")
		info.outputfile.write("[")
		for l in info.gv_reverse_map[gv_addr]:
			info.outputfile.write(hex(l[0]) + " ")
			info.outputfile.write(hex(l[1]) + " ")
		info.outputfile.write("]\n")
	info.outputfile.close()


	info.outputfile = open(os.path.realpath(info.args.output), "w") 
	for gv_addr in sorted(info.gvtohv_map):
		info.outputfile.write("*\n")
		info.outputfile.write("gv_addr: " + hex(gv_addr) + "\n")
		info.outputfile.write("[")
		for heap_var_init_insn_addr in info.gvtohv_map[gv_addr]:
			info.outputfile.write(hex(heap_var_init_insn_addr) + " ")
		info.outputfile.write("]\n")
	info.outputfile.close()
	'''

def makeregistersymbolic(s):
	info.state.regs.rax = info.state.solver.BVS(s + "rax", 64)
	info.state.regs.rbx = info.state.solver.BVS(s + "rbx", 64)
	info.state.regs.rcx = info.state.solver.BVS(s + "rcx", 64)
	info.state.regs.rdx = info.state.solver.BVS(s + "rdx", 64)
	info.state.regs.rdi = info.state.solver.BVS(s + "rdi", 64)
	info.state.regs.rsi = info.state.solver.BVS(s + "rsi", 64)
	info.state.regs.r8 = info.state.solver.BVS(s + "r8", 64)
	info.state.regs.r9 = info.state.solver.BVS(s + "r9", 64)
	info.state.regs.r10 = info.state.solver.BVS(s + "r10", 64)
	info.state.regs.r11 = info.state.solver.BVS(s + "r11", 64)
	info.state.regs.r12 = info.state.solver.BVS(s + "r12", 64)
	info.state.regs.r13 = info.state.solver.BVS(s + "r13", 64)
	info.state.regs.r14 = info.state.solver.BVS(s + "r14", 64)
	info.state.regs.r15 = info.state.solver.BVS(s + "r15", 64)


def check_lock_set_changed(old_d, new_d, start_insn_addr, end_insn_addr):
	changed = False
	addr = start_insn_addr
	while addr <= end_insn_addr and addr != -1:
		if addr in old_d and addr not in new_d:
			changed = True
			break
		if addr not in old_d and addr in new_d:
			changed = True
			break
		if addr in old_d and addr in new_d:
			if old_d[addr] != new_d[addr]:
				changed = True
				break
		addr = findnextinsaddr(addr)
	return changed


def lock_variable_analysis():

	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("lock_variable_analysis\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("lock_variable_analysis")

	#print("lock_variable_analysis")
	info.locksetfile = info.binaryfile + "_lockset_tmp_file"
	info.ots_once_caller_callee_mapfile = info.binaryfile + "_ots_once_caller_callee_map_tmp_file"

	# if previous analysis intermediate results exist
	# use and load these results
	if os.path.exists(info.locksetfile):

		info.lockset = {}

		f = open(info.locksetfile, "r")
		lines = f.readlines()

		addr = 0
		locks = set()
		index = 0
		line_num = 0

		for line in lines:
			if "*" in line:
				if addr != 0:
					info.lockset[addr] = copy.deepcopy(locks)
					addr = 0
					locks = set()
					index = 0

			else:
				if index == 0:
					addr = int(line, 16)
				elif index == 1:
					lockstrs = line[line.index("[") + 1: line.index("]")].strip().split()
					for lockstr in lockstrs:
						locks.add(int(lockstr, 16))

				index = index + 1

			if line_num == len(lines) - 1:
				if addr != 0:
					info.lockset[addr] = copy.deepcopy(locks)
					addr = 0
					locks = set()
					index = 0

			line_num = line_num + 1

		f.close()

		#for addr in sorted(info.lockset):
		#	print("*")
		#	print(hex(addr))
		#	print("[", end='')
		#	for l in info.lockset[addr]:
		#		print(hex(l) + " ", end='')
		#	print("]")


	
	# handle ots_once_caller_callee_map
	if os.path.exists(info.ots_once_caller_callee_mapfile):
		f = open(info.ots_once_caller_callee_mapfile, "r")
		lines = f.readlines()

		addr = 0
		callees = set()
		index = 0
		line_num = 0

		for line in lines:
			if "*" in line:
				if addr != 0:
					info.ots_once_caller_callee_map[addr] = copy.deepcopy(callees)
					addr = 0
					callees = set()
					index = 0

			else:
				if index == 0:
					addr = int(line, 16)
				elif index == 1:
					calleestrs = line[line.index("[") + 1: line.index("]")].strip().split()
					for calleestr in calleestrs:
						callees.add(int(calleestr, 16))

				index = index + 1

			if line_num == len(lines) - 1:
				if addr != 0:
					info.ots_once_caller_callee_map[addr] = copy.deepcopy(callees)
					addr = 0
					callees = set()
					index = 0

			line_num = line_num + 1

		f.close()

		#for caller in sorted(info.ots_once_caller_callee_map):
		#	print("*")
		#	print(hex(caller))
		#	for callee in sorted(info.ots_once_caller_callee_map[caller]):
		#		print(hex(callee))


	if os.path.exists(info.locksetfile) and os.path.exists(info.ots_once_caller_callee_mapfile):
		return


	# check if we have sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock functions
	#if "sgx_thread_mutex_lock" in info.func_name_map:
	#	info.hasmutex = 1
	#elif "pthread_mutex_lock" in info.func_name_map or "oe_pthread_mutex_lock" in info.func_name_map or "mbedtls_mutex_lock" in info.func_name_map or "oe_mutex_lock" in info.func_name_map:
	#	info.hasmutex = 1


	#if "sgx_spin_lock" in info.func_name_map:
	#	info.hasspin = 1
	#elif "oe_pthread_spin_lock" in info.func_name_map or "oe_spin_lock" in info.func_name_map:
	#	info.hasspin = 1

	#print(hex(info.hasmutex))
	#print(hex(info.hasspin))


	sgx_thread_mutex_lock_func_addresses = []
	sgx_thread_mutex_unlock_func_addresses = []
	sgx_spin_lock_func_addresses = []
	sgx_spin_unlock_func_addresses = []
	sgx_rwlock_func_addresses = []
	sgx_barrier_func_addresses = []
	sgx_reentrant_mutex_lock_func_addresses = []
	sgx_condvar_func_addresses = []
	sgx_once_func_addresses = []


	for mutex_lock_function in info.mutex_lock_functions:
		if mutex_lock_function in info.func_name_map:
			info.hasmutex = 1
			sgx_thread_mutex_lock_func_addresses.append(info.func_name_map[mutex_lock_function][0])

	for mutex_unlock_function in info.mutex_unlock_functions:
		if mutex_unlock_function in info.func_name_map:
			sgx_thread_mutex_unlock_func_addresses.append(info.func_name_map[mutex_unlock_function][0])

	for spin_lock_function in info.spin_lock_functions:
		if spin_lock_function in info.func_name_map:
			info.hasspin = 1
			sgx_spin_lock_func_addresses.append(info.func_name_map[spin_lock_function][0])

	for spin_unlock_function in info.spin_unlock_functions:
		if spin_unlock_function in info.func_name_map:
			sgx_spin_unlock_func_addresses.append(info.func_name_map[spin_unlock_function][0])

	# special handling for indirectly called lock functions
	# do a intra-procedural analysis for functions containing indirect lock/unlock call instructions

	# find indirect calls

	indirect_call_sites = []
	indirect_call_site_func_addrs = set()

	count = 0
	for addr in sorted(info.callinsnmap):
		#print("*")
		#print(hex(addr))
		#print(hex(get_enclosing_func_addr(addr)))

		if info.args.app == True and get_enclosing_func_addr_1(addr) in info.intel_sgx_sdk_func_insn_addrs:
			continue

		if info.callinsnmap[addr] == -1 and len(info.insnsmap[addr].operands) == 1 and not info.insnsmap[addr].operands[0].type == X86_OP_IMM:
			#print("*")
			#print(hex(get_enclosing_func_addr_1(addr)))
			#print(hex(addr))
			#print(info.insnlinesmap[addr])
			indirect_call_sites.append([get_enclosing_func_addr_1(addr), addr])
			indirect_call_site_func_addrs.add(get_enclosing_func_addr_1(addr))
			count = count + 1
	#print(count)

	# quick filter: check whether the function asm lines has related strings

	indirect_call_site_func_possible_funcs = set()

	for addr in sorted(indirect_call_site_func_addrs):
		#print("*")
		#print(hex(addr))

		add = addr

		#print(hex(info.func_addr_map[addr][1]))
		while add < info.func_addr_map[addr][1] and add != -0x1:
			#print("+")
			#print(hex(add))
			if ("_lock" in info.insnlinesmap[add] or "_unlock" in info.insnlinesmap[add] or "_LOCK" in info.insnlinesmap[add] or "_UNLOCK" in info.insnlinesmap[add]) \
				and not "call" in info.insnlinesmap[add]:
				#print("+")
				#print(hex(add))
				#print(info.insnlinesmap[add])
				for func in info.mutex_lock_functions:
					#print(func)
					if func in info.insnlinesmap[add]:
						indirect_call_site_func_possible_funcs.add(get_enclosing_func_addr_1(add))
						break
				for func in info.mutex_unlock_functions:
					if func in info.insnlinesmap[add]:
						indirect_call_site_func_possible_funcs.add(get_enclosing_func_addr_1(add))
						break
				for func in info.spin_lock_functions:
					if func in info.insnlinesmap[add]:
						indirect_call_site_func_possible_funcs.add(get_enclosing_func_addr_1(add))
						break
				for func in info.spin_unlock_functions:
					if func in info.insnlinesmap[add]:
						indirect_call_site_func_possible_funcs.add(get_enclosing_func_addr_1(add))
						break
				if "SPIN_LOCK" in info.insnlinesmap[add]:
						indirect_call_site_func_possible_funcs.add(get_enclosing_func_addr_1(add))
						break

			add = findnextinsaddr(add)


	# intra-procedural analysis

	MAX_ITERATE = 10
	MAX_SINGLE_ITERATE = 2
	loop_times_map = {}

	mutex_lock_func_addrs = []
	mutex_unlock_func_addrs = []
	spin_lock_func_addrs = []
	spin_unlock_func_addrs = []

	for mutex_lock_function in info.mutex_lock_functions:
		if mutex_lock_function in info.func_name_map:
			mutex_lock_func_addrs.append(info.func_name_map[mutex_lock_function][0])

	for mutex_unlock_function in info.mutex_unlock_functions:
		if mutex_unlock_function in info.func_name_map:
			mutex_unlock_func_addrs.append(info.func_name_map[mutex_unlock_function][0])

	for spin_lock_function in info.spin_lock_functions:
		if spin_lock_function in info.func_name_map:
			spin_lock_func_addrs.append(info.func_name_map[spin_lock_function][0])

	for spin_unlock_function in info.spin_unlock_functions:
		if spin_unlock_function in info.func_name_map:
			spin_unlock_func_addrs.append(info.func_name_map[spin_unlock_function][0])


	#print("mutex_lock_func_addrs")
	#for mutex_lock_func_addr in mutex_lock_func_addrs:
	#	print(hex(mutex_lock_func_addr))

	#print("mutex_unlock_func_addrs")
	#for mutex_unlock_func_addr in mutex_unlock_func_addrs:
	#	print(hex(mutex_unlock_func_addr))


	#print("spin_lock_func_addrs")
	#for spin_lock_func_addr in spin_lock_func_addrs:
	#	print(hex(spin_lock_func_addr))

	#print("spin_unlock_func_addrs")
	#for spin_unlock_func_addr in spin_unlock_func_addrs:
	#	print(hex(spin_unlock_func_addr))


	mutex_lock_indirect_callsite_addrs = set()
	mutex_unlock_indirect_callsite_addrs = set()
	spin_lock_indirect_callsite_addrs = set()
	spin_unlock_indirect_callsite_addrs = set()


	mutex_lock_indirect_jmpsite_addrs = set()
	mutex_unlock_indirect_jmpsite_addrs = set()
	spin_lock_indirect_jmpsite_addrs = set()
	spin_unlock_indirect_jmpsite_addrs = set()


	#for addr in sorted(indirect_call_site_func_possible_funcs):
	#	print("*")
	#	print(hex(addr))


	for addr in sorted(indirect_call_site_func_possible_funcs):
		#print("*")
		#print(hex(addr))
		#print(hex(info.func_addr_map[addr][1]))

		func_start_addr = addr
		func_end_addr = info.func_addr_map[addr][1]


		info.state = info.project.factory.entry_state(addr=addr, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

		makeregistersymbolic("init_")

		info.states = [info.state]
		loop_times = 0

		while True:
			if not info.states:
				break

			info.state = info.states.pop(0)

			if info.state.addr < func_start_addr or info.state.addr > func_end_addr:
				continue

			#print(hex(info.state.addr))
			#print(len(info.states))


			if info.state.addr not in info.insnsmap:
				continue

			insn = info.insnsmap[info.state.addr]



			if insn.id == X86_INS_RET or insn.id == X86_INS_RETF or insn.id == X86_INS_RETFQ:
				continue

			if info.state.addr in info.backedgemap:
				#print("loop_times: " + str(loop_times))
				if loop_times <= MAX_ITERATE:
					loop_times = loop_times + 1
				else:
					continue

			if not info.state.addr in loop_times_map:
				loop_times_map[info.state.addr] = 0
			elif loop_times_map[info.state.addr] <= MAX_SINGLE_ITERATE: 
				loop_times_map[info.state.addr] = loop_times_map[info.state.addr] + 1
			else:
				continue



			if insn.id == X86_INS_CALL and findnextinsaddr(info.state.addr) != -0x1 and findnextinsaddr(info.state.addr) < func_end_addr:

				# examine call instruction operands
				if len(insn.operands) == 1:
					if insn.operands[0].type == X86_OP_REG and not info.state.registers.load(insn.reg_name(insn.operands[0].value.reg)).symbolic:
						callee_func_addr = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.reg)))
						#print("+" + hex(callee_func_addr))
						if callee_func_addr in mutex_lock_func_addrs:
							mutex_lock_indirect_callsite_addrs.add(info.state.addr)
						if callee_func_addr in mutex_unlock_func_addrs:
							mutex_unlock_indirect_callsite_addrs.add(info.state.addr)
						if callee_func_addr in spin_lock_func_addrs:
							spin_lock_indirect_callsite_addrs.add(info.state.addr)
						if callee_func_addr in spin_unlock_func_addrs:
							spin_unlock_indirect_callsite_addrs.add(info.state.addr)
					if insn.operands[0].type == X86_OP_MEM and insn.reg_name(insn.operands[0].value.mem.base):
						callee_addr = 0
						if insn.reg_name(insn.operands[0].value.mem.index):
							if not info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index)).symbolic:
								base = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
								if insn.reg_name(insn.operands[0].value.mem.base) == "rip":
									base = findnextinsaddr(info.state.addr)
								index = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index)))
								scale = insn.operands[0].value.mem.scale
								disp = insn.operands[0].value.mem.disp
								mem_addr = base + index * scale + disp
								#print("+")
								#print(hex(info.state.addr))
								#print(hex(mem_addr))
								#print(hex(read_variable_initial_value_in_binary(mem_addr, 8)))
								#print(hex(v_dyn_addr_to_binary_offset(mem_addr)))
								if v_dyn_addr_to_binary_offset(mem_addr) != -1:
									callee_addr = static_addr_to_v_dyn_addr(read_variable_initial_value_in_binary(mem_addr, 8))

						else:
							base = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
							if insn.reg_name(insn.operands[0].value.mem.base) == "rip":
								base = findnextinsaddr(info.state.addr)
							index = 0
							scale = insn.operands[0].value.mem.scale
							disp = insn.operands[0].value.mem.disp
							mem_addr = base + index * scale + disp
							#print("+")
							#print(hex(info.state.addr))
							#print(hex(mem_addr))
							#print(hex(read_variable_initial_value_in_binary(mem_addr, 8)))
							#print(hex(v_dyn_addr_to_binary_offset(mem_addr)))
							if v_dyn_addr_to_binary_offset(mem_addr) != -1:
								callee_addr = static_addr_to_v_dyn_addr(read_variable_initial_value_in_binary(mem_addr, 8))
						if callee_addr != 0:
							#print("+")
							#print(hex(callee_addr))
							if callee_addr in mutex_lock_func_addrs:
								mutex_lock_indirect_callsite_addrs.add(info.state.addr)
							if callee_addr in mutex_unlock_func_addrs:
								mutex_unlock_indirect_callsite_addrs.add(info.state.addr)
							if callee_addr in spin_lock_func_addrs:
								spin_lock_indirect_callsite_addrs.add(info.state.addr)
							if callee_addr in spin_unlock_func_addrs:
								spin_unlock_indirect_callsite_addrs.add(info.state.addr)


				#print("*")
				#print("call insn")
				#print(hex(info.state.addr))
				#print(len(insn.operands))
				#print(insn.operands[0].type)
				#print("*")

				rsp = info.state.regs.rsp
				rbp = info.state.regs.rbp
				rbx = info.state.regs.rbx
				r12 = info.state.regs.r12
				r13 = info.state.regs.r13
				r14 = info.state.regs.r14
				r15 = info.state.regs.r15

				info.state = info.project.factory.entry_state(addr=info.state.addr, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
				info.state.regs.rsp = rsp
				info.state.regs.rbp = rbp
				makeregistersymbolic("sym_" + hex(info.state.addr) + "_")
				info.state.regs.rbx = rbx
				info.state.regs.r12 = r12
				info.state.regs.r13 = r13
				info.state.regs.r14 = r14
				info.state.regs.r15 = r15

				info.state.regs.rip = findnextinsaddr(info.state.addr)


				info.states.append(info.state)
				continue

			if insn.id == X86_INS_JMP:
				#print("+" + hex(info.state.addr))

				# examine jmp instruction operands
				if len(insn.operands) == 1:
					if insn.operands[0].type == X86_OP_REG and not info.state.registers.load(insn.reg_name(insn.operands[0].value.reg)).symbolic:
						callee_func_addr = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.reg)))
						#print("+" + hex(callee_func_addr))
						if callee_func_addr in mutex_lock_func_addrs:
							mutex_lock_indirect_jmpsite_addrs.add(info.state.addr)
						if callee_func_addr in mutex_unlock_func_addrs:
							mutex_unlock_indirect_jmpsite_addrs.add(info.state.addr)
						if callee_func_addr in spin_lock_func_addrs:
							spin_lock_indirect_jmpsite_addrs.add(info.state.addr)
						if callee_func_addr in spin_unlock_func_addrs:
							spin_unlock_indirect_jmpsite_addrs.add(info.state.addr)
					if insn.operands[0].type == X86_OP_MEM and insn.reg_name(insn.operands[0].value.mem.base):
						callee_addr = 0
						#print("+" + hex(info.state.addr))
						if insn.reg_name(insn.operands[0].value.mem.index):
							if not info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index)).symbolic:
								base = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
								if insn.reg_name(insn.operands[0].value.mem.base) == "rip":
									base = findnextinsaddr(info.state.addr)
								index = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.index)))
								scale = insn.operands[0].value.mem.scale
								disp = insn.operands[0].value.mem.disp
								mem_addr = base + index * scale + disp
								#print("+")
								#print(hex(info.state.addr))
								#print(hex(mem_addr))
								#print(hex(read_variable_initial_value_in_binary(mem_addr, 8)))
								#print(hex(v_dyn_addr_to_binary_offset(mem_addr)))
								if v_dyn_addr_to_binary_offset(mem_addr) != -1:
									callee_addr = static_addr_to_v_dyn_addr(read_variable_initial_value_in_binary(mem_addr, 8))

						else:
							base = info.state.solver.eval(info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
							if insn.reg_name(insn.operands[0].value.mem.base) == "rip":
								base = findnextinsaddr(info.state.addr)
							index = 0
							scale = insn.operands[0].value.mem.scale
							disp = insn.operands[0].value.mem.disp
							mem_addr = base + index * scale + disp
							#print("+")
							#print(hex(info.state.addr))
							#print(hex(mem_addr))
							#print(hex(read_variable_initial_value_in_binary(mem_addr, 8)))
							#print(hex(v_dyn_addr_to_binary_offset(mem_addr)))
							if v_dyn_addr_to_binary_offset(mem_addr) != -1:
								callee_addr = static_addr_to_v_dyn_addr(read_variable_initial_value_in_binary(mem_addr, 8))
						if callee_addr != 0:
							#print("+")
							#print(hex(callee_addr))
							if callee_addr in mutex_lock_func_addrs:
								mutex_lock_indirect_jmpsite_addrs.add(info.state.addr)
							if callee_addr in mutex_unlock_func_addrs:
								mutex_unlock_indirect_jmpsite_addrs.add(info.state.addr)
							if callee_addr in spin_lock_func_addrs:
								spin_lock_indirect_jmpsite_addrs.add(info.state.addr)
							if callee_addr in spin_unlock_func_addrs:
								spin_unlock_indirect_jmpsite_addrs.add(info.state.addr)


				#print("*")
				#print("call insn")
				#print(hex(info.state.addr))
				#print(len(insn.operands))
				#print(insn.operands[0].type)
				#print("*")
				continue


			info.succs = []
			try:
				#skip = 0
				#print("+")
				info.succs = info.project.factory.successors(info.state, num_inst=1).successors
			except:
				pass


			#print("+")
			#print(hex(info.state.addr) + "succs: ")

			for succ in info.succs:
				#print(hex(succ.addr))
				if not succ.regs.rip.symbolic:
					#print("++")
					info.states.append(succ)


			gc.collect()


		gc.collect()


	'''
	print("mutex_lock_indirect_callsite_addrs")
	for mutex_lock_indirect_callsite_addr in sorted(mutex_lock_indirect_callsite_addrs):
		print(hex(mutex_lock_indirect_callsite_addr))

	print("mutex_unlock_indirect_callsite_addrs")
	for mutex_unlock_indirect_callsite_addr in sorted(mutex_unlock_indirect_callsite_addrs):
		print(hex(mutex_unlock_indirect_callsite_addr))


	print("spin_lock_indirect_callsite_addrs")
	for spin_lock_indirect_callsite_addr in sorted(spin_lock_indirect_callsite_addrs):
		print(hex(spin_lock_indirect_callsite_addr))

	print("spin_unlock_indirect_callsite_addrs")
	for spin_unlock_indirect_callsite_addr in sorted(spin_unlock_indirect_callsite_addrs):
		print(hex(spin_unlock_indirect_callsite_addr))


	print("mutex_lock_indirect_jmpsite_addrs")
	for mutex_lock_indirect_jmpsite_addr in sorted(mutex_lock_indirect_jmpsite_addrs):
		print(hex(mutex_lock_indirect_jmpsite_addr))

	print("mutex_unlock_indirect_jmpsite_addrs")
	for mutex_unlock_indirect_jmpsite_addr in sorted(mutex_unlock_indirect_jmpsite_addrs):
		print(hex(mutex_unlock_indirect_jmpsite_addr))


	print("spin_lock_indirect_jmpsite_addrs")
	for spin_lock_indirect_jmpsite_addr in sorted(spin_lock_indirect_jmpsite_addrs):
		print(hex(spin_lock_indirect_jmpsite_addr))

	print("spin_unlock_indirect_jmpsite_addrs")
	for spin_unlock_indirect_jmpsite_addr in sorted(spin_unlock_indirect_jmpsite_addrs):
		print(hex(spin_unlock_indirect_jmpsite_addr))


	'''


	# handle other specific lock and unlock functions
	for func_name in info.func_name_map:
		if "Spinlock" in func_name and "lock" in func_name:
			info.hasspin = 1
			sgx_spin_lock_func_addresses.append(info.func_name_map[func_name][0])
		if "Spinlock" in func_name and "unlock" in func_name:
			sgx_spin_unlock_func_addresses.append(info.func_name_map[func_name][0])

		if ("Mutex" in func_name and "lock" in func_name and "trylock" not in func_name and "unlock" not in func_name) or (func_name == "__lock"):
			info.hasmutex = 1
			sgx_thread_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex lock")
			#print(hex(info.func_name_map[func_name][0]))

		if ("Mutex" in func_name and "unlock" in func_name) or (func_name == "__unlock"):
			sgx_thread_mutex_unlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex unlock")
			#print(hex(info.func_name_map[func_name][0]))

		# rwlock
		if "RwLock" in func_name and ("read" in func_name or "write" in func_name) and "try_read" not in func_name and "try_write" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "RwLock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock unlock")
			#print(hex(info.func_name_map[func_name][0]))

		if "oe_pthread_rwlock" in func_name and ("rdlock" in func_name or "wrlock" in func_name):
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "oe_pthread_rwlock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

		if "RWLock" in func_name and ("read" in func_name or "write" in func_name) and "try_read" not in func_name and "try_write" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "RWLock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock unlock")
			#print(hex(info.func_name_map[func_name][0]))

		# barrier
		if "Barrier" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_barrier_func_addresses.append(info.func_name_map[func_name][0])


		# reentrant mutex
		if "Reentrant" in func_name and "lock" in func_name and "trylock" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_reentrant_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "Reentrant" in func_name and "unlock" in func_name:
			sgx_reentrant_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex unlock")
			#print(hex(info.func_name_map[func_name][0]))


		# condition variable
		if "Condvar" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "Condvar" in func_name and ("signal" in func_name or "broadcast" in func_name or "notify" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "sgx_thread_cond" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "sgx_thread_cond" in func_name and ("signal" in func_name or "broadcast" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "oe_pthread_cond" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "oe_pthread_cond" in func_name and ("signal" in func_name or "broadcast" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])


		# once variable
		if "oe_once" in func_name or "oe_pthread_once" in func_name or "pthread_once" in func_name or ("Once" in func_name and "call_once" in func_name):
			sgx_once_func_addresses.append(info.func_name_map[func_name][0])

	'''
	print("*")
	for addr in sgx_spin_lock_func_addresses:
		print(hex(addr))
	print("*")
	for addr in sgx_spin_unlock_func_addresses:
		print(hex(addr))
	print("*")
	for addr in sgx_thread_mutex_lock_func_addresses:
		print(hex(addr))
	print("*")
	for addr in sgx_thread_mutex_unlock_func_addresses:
		print(hex(addr))
	print("*")
	for addr in sgx_once_func_addresses:
		print(hex(addr))
	'''

	# once var
	oncesiteaddresses = []
	for addr in sorted(info.callinsnmap):
		if info.callinsnmap[addr] in sgx_once_func_addresses and not addr in info.whitelist:

			if info.args.app == True and addr in info.intel_sgx_sdk_func_insn_addrs:
				continue

			oncesiteaddresses.append(addr)

	#for addr in sorted(oncesiteaddresses):
	#	print(hex(addr))
	#print("+")

	# resolve the once guarded functions within one basic block
	for addr in oncesiteaddresses:
		#print("*")
		#print(hex(addr))
		#print(hex(get_enclosing_bb_addr(addr)))

		resolve_start = 0
		#resolve_end = 0

		if get_enclosing_bb_addr(addr) == -1 or get_enclosing_bb_addr(addr) == addr:
			resolve_start = -1
			#resolve_end = -1
			#print(hex(addr))

		else:
			resolve_start = get_enclosing_bb_addr(addr)
		#	resolve_end = findpreviousinsaddr(addr)

		#print("*")
		#print(hex(addr))
		#print(hex(resolve_start))
		#print(hex(resolve_end))

		once_guard_func = -1

		if resolve_start != -1:

			info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

			makeregistersymbolic("init_")
			info.state.regs.rsp = initial_rsp = info.state.solver.BVS("rsp", 64)
			info.state.regs.rbp = info.state.solver.BVS("rbp", 64)

			info.states = [info.state]
			#info.states.append(info.state)

			while True:
				if not info.states:
					break

				info.state = info.states.pop(0)

				if info.state.addr == addr:
					break

				#print(hex(info.state.addr))

				info.succs = []
				info.succs = info.project.factory.successors(info.state, num_inst=1).successors
				info.states.extend(info.succs)


			#print(info.state.regs.rdi)
			#print(info.state.regs.rdi.symbolic)
			if not info.state.regs.rsi.symbolic:
				once_guard_func = info.state.solver.eval(info.state.regs.rsi)
				#print("*")
				#print(hex(addr))
				#print(hex(once_guard_func))


		if once_guard_func != -1:
			if once_guard_func in info.func_addr_map:
				#print("*")
				#print(hex(addr))
				#print(hex(get_enclosing_func_addr_1(addr)))
				#print(hex(once_guard_func))
				if get_enclosing_func_addr_1(addr) != -1:
					if not get_enclosing_func_addr_1(addr) in info.ots_once_caller_callee_map:
						s = set()
						s.add(once_guard_func)
						info.ots_once_caller_callee_map[get_enclosing_func_addr_1(addr)] = s
						#print("a")
						#print(info.ots_once_caller_callee_map[get_enclosing_func_addr_1(addr)])
					else:
						info.ots_once_caller_callee_map[get_enclosing_func_addr_1(addr)].add(once_guard_func)
						#print("b")
						#print(info.ots_once_caller_callee_map[get_enclosing_func_addr_1(addr)])
					insn_addr = once_guard_func
					while insn_addr < info.func_addr_map[once_guard_func][1] and insn_addr != -0x1:
						info.lockset[insn_addr] = set()
						info.lockset[insn_addr].add(-2)
						insn_addr = findnextinsaddr(insn_addr)

			#print("*")
			#print(hex(once_guard_func))
			#print("*")

	#for caller in sorted(info.ots_once_caller_callee_map):
	#	print("*")
	#	print(hex(caller))
	#	for callee in sorted(info.ots_once_caller_callee_map[caller]):
	#		print(hex(callee))

	# save ots_once_caller_callee_map to file
	
	# save intermediate results in tmp file
	f = open(info.ots_once_caller_callee_mapfile, "w")
	for addr in sorted(info.ots_once_caller_callee_map):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write("[")
		for l in info.ots_once_caller_callee_map[addr]:
			f.write(hex(l) + " ")
		f.write("]" + "\n")

	f.close()

	# resolve other self-defined once guarded critical sections
	#insn = info.insnsmap[0x423da3]
	#print(dir(insn))
	#print(insn.mnemonic)
	#print(insn.id)

	# find instructions with lock prefix and xchg instructions

	lockxchgaddresses = []
	lockcmpxchgaddresses = []

	for addr in sorted(info.insnsmap):
		insn = info.insnsmap[addr]
		# including xchg, lock xchg, cmpxchg and lock cmpxchg
		if "xchg" in insn.mnemonic:

			#print(hex(addr))
			#print(info.insnlinesmap[addr].strip())

			# do not bother with nonecode addresses
			if not addr in info.nonecodeaddresses and len(insn.operands) == 2 and insn.operands[0].type == X86_OP_MEM:
				func_addr = get_enclosing_func_addr_1(addr)
				if not func_addr in info.whitelist:
					if not "cmpxchg" in insn.mnemonic:
						lockxchgaddresses.append(addr)
					else:
						lockcmpxchgaddresses.append(addr)

	#print("\n\nlockxchgaddresses:")
	#for addr in lockxchgaddresses:
	#	print(hex(addr))
	#	print(info.insnlinesmap[addr].strip())

	#print("\n\nlockcmpxchgaddresses:")
	#for addr in lockcmpxchgaddresses:
	#	print(hex(addr))
	#	print(info.insnlinesmap[addr].strip())

	# handle once via self-defined functions
	self_once_funcs = set()
	self_once_funcs_itself = set()

	for addr in lockcmpxchgaddresses:
		func_addr = get_enclosing_func_addr_1(addr)
		self_once_funcs.add(func_addr)
		self_once_funcs_itself.add(func_addr)
		if func_addr in info.callgraph_reverse:
			for caller in info.callgraph_reverse[func_addr]:
				caller_root = caller[0]
				self_once_funcs.add(caller_root)

				# find call callees of caller_root recursively
				worklist = [caller_root]
				visited = [caller_root]
				visitedresult = [caller_root]

				while worklist:
					worklist_func_addr = worklist.pop(0)
					#print("*")
					#print(hex(worklist_func_addr))
					#print(hex(get_enclosing_func_end_addr(worklist_func_addr)))				
					#print("**")
					insn = worklist_func_addr
					while insn <= get_enclosing_func_end_addr(worklist_func_addr) and insn != -1:
						#print(hex(insn))

						if insn in info.insnsmap:
							if info.insnsmap[insn].id == X86_INS_CALL:
								if info.callinsnmap[insn] != -1 and info.callinsnmap[insn] not in info.whitelist:
									if info.callinsnmap[insn] not in visited and info.callinsnmap[insn] in info.func_addr_map \
										and info.func_addr_map[info.callinsnmap[insn]][0] != ".plt.got":

										# check the function is only called by the caller, otherwise stop exploring this cfg node
										worklist_callee = info.callinsnmap[insn]
										worklist_callers = set()
										if worklist_callee in info.callgraph_reverse:
											for worklist_caller in info.callgraph_reverse[worklist_callee]:
												worklist_callers.add(worklist_caller[0])
											if len(worklist_callers) == 1:
												worklist.append(worklist_callee)
												visitedresult.append(worklist_callee)
										visited.append(worklist_callee)
										#print("+++++")
										#print(visited)
										#print(hex(info.callinsnmap[insn]))

							elif info.insnsmap[insn].id == X86_INS_JMP:
								if info.jmpinsnmap[insn][0] != -1 and info.jmpinsnmap[insn][0] not in info.whitelist:
									if info.jmpinsnmap[insn][0] < get_enclosing_func_addr(insn) or info.jmpinsnmap[insn][0] > get_enclosing_func_end_addr(insn):
										if info.jmpinsnmap[insn][0] not in visited and info.jmpinsnmap[insn][0] in info.func_addr_map \
											and info.func_addr_map[info.jmpinsnmap[insn][0]][0] != ".plt.got":

											# check the function is only called by the caller, otherwise stop exploring this cfg node
											worklist_callee = info.jmpinsnmap[insn][0]
											worklist_callers = set()
											if worklist_callee in info.callgraph_reverse:
												for worklist_caller in info.callgraph_reverse[worklist_callee]:
													worklist_callers.add(worklist_caller[0])
												if len(worklist_callers) == 1:
													worklist.append(worklist_callee)
													visitedresult.append(worklist_callee)
											visited.append(worklist_callee)
											#print("+++++")
											#print(visited)
											#print(hex(info.jmpinsnmap[insn][0]))

						insn = findnextinsaddr(insn)

				# check if these callers are only called by one caller
				for visitedcallee in sorted(visited):
					if visitedcallee in info.callgraph_reverse:
						visitedcallers = set()
						for visitedcaller in info.callgraph_reverse[visitedcallee]:
							visitedcallers.add(visitedcaller[0])
						if len(visitedcallers) == 1:
							self_once_funcs.add(visitedcallee)

	# remove the defining functions
	for self_once_func_itself in sorted(self_once_funcs_itself):
		self_once_funcs.remove(self_once_func_itself)
		#print(hex(self_once_func_itself))

	for self_once_func in self_once_funcs:
		#print(hex(self_once_func))
		#print(info.func_addr_map[self_once_func][0])

		insn_addr = self_once_func
		while insn_addr < info.func_addr_map[self_once_func][1] and insn_addr != -0x1:
			info.lockset[insn_addr] = set()
			info.lockset[insn_addr].add(-3)
			insn_addr = findnextinsaddr(insn_addr)

	#sgx_thread_mutex_lock_func_addr = info.func_name_map["sgx_thread_mutex_lock"][0]
	#sgx_thread_mutex_unlock_func_addr = info.func_name_map["sgx_thread_mutex_unlock"][0]
	#sgx_spin_lock_func_addr = info.func_name_map["sgx_spin_lock"][0]
	#sgx_spin_unlock_func_addr = info.func_name_map["sgx_spin_unlock"][0]

	#print(hex(sgx_thread_mutex_lock_func_addr))
	#print(hex(sgx_thread_mutex_unlock_func_addr))
	#print(hex(sgx_spin_lock_func_addr))
	#print(hex(sgx_spin_unlock_func_addr))

	# a local dict from lock site addr to [type, transfer_type]
	locksitetypemap = {}

	# get call site of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock
	for addr in sorted(info.callinsnmap):

		if info.args.app == True and addr in info.intel_sgx_sdk_func_insn_addrs:
			continue

		if info.callinsnmap[addr] in sgx_thread_mutex_lock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [0, 0]
		elif info.callinsnmap[addr] in sgx_thread_mutex_unlock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [1, 0]
		elif info.callinsnmap[addr] in sgx_spin_lock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [2, 0]
		elif info.callinsnmap[addr] in sgx_spin_unlock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [3, 0]

	# get jmp site of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock
	for addr in sorted(info.jmpinsnmap):

		if info.args.app == True and addr in info.intel_sgx_sdk_func_insn_addrs:
			continue

		if info.jmpinsnmap[addr][0] in sgx_thread_mutex_lock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [0, 1]
		elif info.jmpinsnmap[addr][0] in sgx_thread_mutex_unlock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [1, 1]
		elif info.jmpinsnmap[addr][0] in sgx_spin_lock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [2, 1]
		elif info.jmpinsnmap[addr][0] in sgx_spin_unlock_func_addresses:
			info.locksiteaddr.append(addr)
			locksitetypemap[addr] = [3, 1]


	# add call site of indirect call of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock

	#print("mutex_lock_indirect_callsite_addrs")
	for mutex_lock_indirect_callsite_addr in sorted(mutex_lock_indirect_callsite_addrs):
		#print(hex(mutex_lock_indirect_callsite_addr))
		info.locksiteaddr.append(mutex_lock_indirect_callsite_addr)
		locksitetypemap[mutex_lock_indirect_callsite_addr] = [0, 0]

	#print("mutex_unlock_indirect_callsite_addrs")
	for mutex_unlock_indirect_callsite_addr in sorted(mutex_unlock_indirect_callsite_addrs):
		#print(hex(mutex_unlock_indirect_callsite_addr))
		info.locksiteaddr.append(mutex_unlock_indirect_callsite_addr)
		locksitetypemap[mutex_unlock_indirect_callsite_addr] = [1, 0]

	#print("spin_lock_indirect_callsite_addrs")
	for spin_lock_indirect_callsite_addr in sorted(spin_lock_indirect_callsite_addrs):
		#print(hex(spin_lock_indirect_callsite_addr))
		info.locksiteaddr.append(spin_lock_indirect_callsite_addr)
		locksitetypemap[spin_lock_indirect_callsite_addr] = [2, 0]

	#print("spin_unlock_indirect_callsite_addrs")
	for spin_unlock_indirect_callsite_addr in sorted(spin_unlock_indirect_callsite_addrs):
		#print(hex(spin_unlock_indirect_callsite_addr))
		info.locksiteaddr.append(spin_unlock_indirect_callsite_addr)
		locksitetypemap[spin_unlock_indirect_callsite_addr] = [3, 0]



	# add jmp site of indirect call of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock

	#print("mutex_lock_indirect_jmpsite_addrs")
	for mutex_lock_indirect_jmpsite_addr in sorted(mutex_lock_indirect_jmpsite_addrs):
		#print(hex(mutex_lock_indirect_jmpsite_addr))
		info.locksiteaddr.append(mutex_lock_indirect_jmpsite_addr)
		locksitetypemap[mutex_lock_indirect_jmpsite_addr] = [0, 1]

	#print("mutex_unlock_indirect_callsite_addrs")
	for mutex_unlock_indirect_jmpsite_addr in sorted(mutex_unlock_indirect_jmpsite_addrs):
		#print(hex(mutex_unlock_indirect_callsite_addr))
		info.locksiteaddr.append(mutex_unlock_indirect_jmpsite_addr)
		locksitetypemap[mutex_unlock_indirect_jmpsite_addr] = [1, 1]

	#print("spin_lock_indirect_callsite_addrs")
	for spin_lock_indirect_jmpsite_addr in sorted(spin_lock_indirect_jmpsite_addrs):
		#print(hex(spin_lock_indirect_callsite_addr))
		info.locksiteaddr.append(spin_lock_indirect_jmpsite_addr)
		locksitetypemap[spin_lock_indirect_jmpsite_addr] = [2, 1]

	#print("spin_unlock_indirect_callsite_addrs")
	for spin_unlock_indirect_jmpsite_addr in sorted(spin_unlock_indirect_jmpsite_addrs):
		#print(hex(spin_unlock_indirect_callsite_addr))
		info.locksiteaddr.append(spin_unlock_indirect_jmpsite_addr)
		locksitetypemap[spin_unlock_indirect_jmpsite_addr] = [3, 1]

	#for addr in info.locksiteaddr:
	#	print("*")
	#	print(hex(addr))
	#	print(str(locksitetypemap[addr][0]))
	#	print(str(locksitetypemap[addr][1]))

	# resolve the lock variable within one basic block
	for addr in info.locksiteaddr:
		#print("*")
		#print(hex(addr))
		#print(hex(get_enclosing_bb_addr(addr)))

		resolve_start = 0
		#resolve_end = 0

		if get_enclosing_bb_addr(addr) == -1 or get_enclosing_bb_addr(addr) == addr:
			resolve_start = -1
			#resolve_end = -1
			#print(hex(addr))

		else:
			resolve_start = get_enclosing_bb_addr(addr)
		#	resolve_end = findpreviousinsaddr(addr)

		#elif findnextinsaddr(get_enclosing_bb_addr(addr)) == addr:
		#	resolve_start = get_enclosing_bb_addr(addr)
		#	resolve_end = get_enclosing_bb_addr(addr)
		#else:
		#	resolve_start = get_enclosing_bb_addr(addr)
		#	resolve_end = findpreviousinsaddr(addr)

		#print("*")
		#print(hex(addr))
		#print(hex(resolve_start))
		#print(hex(resolve_end))

		gv_addr = -1

		if resolve_start != -1:

			info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

			makeregistersymbolic("init_")
			info.state.regs.rsp = initial_rsp = info.state.solver.BVS("rsp", 64)
			info.state.regs.rbp = info.state.solver.BVS("rbp", 64)

			info.states = [info.state]
			#info.states.append(info.state)

			exe_exception_flag = False
			while True:
				if not info.states:
					break

				info.state = info.states.pop(0)

				if info.state.addr == addr:
					break

				#print(hex(info.state.addr))

				info.succs = []
				try:
					info.succs = info.project.factory.successors(info.state, num_inst=1).successors
				except:
					exe_exception_flag = True
					break
				info.states.extend(info.succs)


			#print(info.state.regs.rdi)
			#print(info.state.regs.rdi.symbolic)
			if not info.state.regs.rdi.symbolic and exe_exception_flag == False:
				gv_addr = info.state.solver.eval(info.state.regs.rdi)
				#print("*")
				#print(hex(addr))
				#print(hex(gv_addr))

		info.locksite[addr] = [gv_addr, locksitetypemap[addr][0], locksitetypemap[addr][1]]

	#for addr in sorted(info.locksite):
	#	print("*")
	#	print(hex(addr))
	#	print(hex(info.locksite[addr][0]))
	#	print(hex(info.locksite[addr][1]))
	#	print(hex(info.locksite[addr][2]))


	# gather information about within which functions locks are acquired

	for addr in sorted(info.locksite):
		if info.locksite[addr][1] == 0:
			if get_enclosing_func_addr(addr) not in info.whitelist:
				if get_enclosing_func_addr(addr) in info.func_mutex_lock_count_map:
					info.func_mutex_lock_count_map[get_enclosing_func_addr(addr)] = info.func_mutex_lock_count_map[get_enclosing_func_addr(addr)] + 1
				else:
					info.func_mutex_lock_count_map[get_enclosing_func_addr(addr)] = 1

		if info.locksite[addr][1] == 1:
			if get_enclosing_func_addr(addr) not in info.whitelist:
				if get_enclosing_func_addr(addr) in info.func_mutex_unlock_count_map:
					info.func_mutex_unlock_count_map[get_enclosing_func_addr(addr)] = info.func_mutex_unlock_count_map[get_enclosing_func_addr(addr)] + 1
				else:
					info.func_mutex_unlock_count_map[get_enclosing_func_addr(addr)] = 1

		if info.locksite[addr][1] == 2:
			if get_enclosing_func_addr(addr) not in info.whitelist:
				if get_enclosing_func_addr(addr) in info.func_spin_lock_count_map:
					info.func_spin_lock_count_map[get_enclosing_func_addr(addr)] = info.func_spin_lock_count_map[get_enclosing_func_addr(addr)] + 1
				else:
					info.func_spin_lock_count_map[get_enclosing_func_addr(addr)] = 1

		if info.locksite[addr][1] == 3:
			if get_enclosing_func_addr(addr) not in info.whitelist:
				if get_enclosing_func_addr(addr) in info.func_spin_unlock_count_map:
					info.func_spin_unlock_count_map[get_enclosing_func_addr(addr)] = info.func_spin_unlock_count_map[get_enclosing_func_addr(addr)] + 1
				else:
					info.func_spin_unlock_count_map[get_enclosing_func_addr(addr)] = 1

	#print("func_mutex_lock_count_map:")
	#for addr in sorted(info.func_mutex_lock_count_map):
	#	print(info.func_addr_map[addr][0])
	#	print(str(info.func_mutex_lock_count_map[addr]))

	#print("func_mutex_unlock_count_map:")
	#for addr in sorted(info.func_mutex_unlock_count_map):
	#	print(info.func_addr_map[addr][0])
	#	print(str(info.func_mutex_unlock_count_map[addr]))

	#print("func_spin_lock_count_map:")
	#for addr in sorted(info.func_spin_lock_count_map):
	#	print(info.func_addr_map[addr][0])
	#	print(str(info.func_spin_lock_count_map[addr]))

	#print("func_spin_unlock_count_map:")
	#for addr in sorted(info.func_spin_unlock_count_map):
	#	print(info.func_addr_map[addr][0])
	#	print(str(info.func_spin_unlock_count_map[addr]))



	# find lock set via data flow
	# intra-procedural
	for addr in sorted(list(info.func_mutex_lock_count_map) + list(info.func_spin_lock_count_map)):
		#print("*")
		#print(hex(addr))
		#print(hex(get_enclosing_func_addr(addr)))
		#print(hex(get_enclosing_func_end_addr(addr)))

		#intra_insn_list = []
		#ad = addr
		#while ad <= get_enclosing_func_end_addr(addr) and ad != -1:
		#	#print(hex(ad))
		#	intra_insn_list.append(ad)
		#	ad = findnextinsaddr(ad)

		#print("*")
		#for insn in intra_insn_list:
		#	print(hex(insn))

		#old_d = copy.deepcopy(info.lockset)
		#s = set()
		#s.add(0x63b138)
		#info.lockset[0x407cca] = s
		#print(check_lock_set_changed(old_d, info.lockset, 0x407c91, 0x407da6))

		#worklist = []
		#worklist.append(addr)

		while True:
			old_d = copy.deepcopy(info.lockset)

			# a pass of data flow propagation
			ad = addr
			while ad <= get_enclosing_func_end_addr(addr) and ad != -1:
				#print(hex(ad))
				#print(info.insn_successor_map[ad])

				# update only insn in the same function
				for succ in info.insn_successor_map[ad]:

					#print("*")
					#print(hex(ad))
					#print(hex(succ[0]))
					#print(hex(succ[1]))

					# copy first
					if succ[0] != -1 and (succ[1] == 0 or succ[1] == 2):
						if ad in info.lockset and succ[0] not in info.lockset:
							info.lockset[succ[0]] = copy.deepcopy(info.lockset[ad])
							#print("1")
							#print(info.lockset[succ[0]])
						elif ad in info.lockset and succ[0] in info.lockset:
							info.lockset[succ[0]] = info.lockset[succ[0]].union(info.lockset[ad])
							#print("2")
							#print(info.lockset[succ[0]])

						#print(hex(ad))
						#print(ad in info.locksite)

					if succ[1] == 1:
						next = findnextinsaddr(ad)
						if next != -1:
							#print(hex(next))
							if ad in info.lockset and next not in info.lockset:
								#print("1")
								info.lockset[next] = copy.deepcopy(info.lockset[ad])
								#print("3")
								#print(info.lockset[next])
							elif ad in info.lockset and next in info.lockset:
								#print("2")
								#print(info.lockset[next])
								#print(ad in info.lockset)
								#print(info.lockset[ad])
								info.lockset[next] = info.lockset[next].union(info.lockset[ad])
								#print("4")
								#print(info.lockset[next])

					# insn is a lock
					if ad in info.locksite and (info.locksite[ad][1] == 0 or info.locksite[ad][1] == 2):
						next = findnextinsaddr(ad)
						if next != -1:
							if next not in info.lockset:
								s = set()
								s.add(info.locksite[ad][0])
								info.lockset[next] = s
								#print("5")
								#print(info.lockset[next])
							
							else:
								s = set()
								s.add(info.locksite[ad][0])
								info.lockset[next] = info.lockset[next].union(s)	
								#print("6")
								#print(info.lockset[next])					
					# insn is an unlock
					elif ad in info.locksite and (info.locksite[ad][1] == 1 or info.locksite[ad][1] == 3):
						next = findnextinsaddr(ad)
						if next != -1:
							if next in info.lockset and info.locksite[ad][0] in info.lockset[next]:
								info.lockset[next] = info.lockset[next].remove(info.locksite[ad][0])
								#print("7")
								#print(info.lockset[next])

								#print(next in info.lockset)
								if info.lockset[next] == None:
									#print("8")
									info.lockset.pop(next, None)
								#print(next in info.lockset)


				ad = findnextinsaddr(ad)

			if not check_lock_set_changed(old_d, info.lockset, addr, get_enclosing_func_end_addr(addr)):
				break

	#for addr in sorted(list(info.func_mutex_lock_count_map) + list(info.func_spin_lock_count_map)):
	#	ad = addr
	#	while ad <= get_enclosing_func_end_addr(addr) and ad != -1:
	#		print("*")
	#		print(hex(ad))
	#		if ad in info.lockset:
				#if len(info.lockset[ad]) >= 2:
				#	print("+")
	#			print("[", end='')
	#			for l in info.lockset[ad]:
	#				print(hex(l) + " ", end='')
	#			print("]")
	#		ad = findnextinsaddr(ad)


	# inter-procedural step 1
	for addr in sorted(list(info.func_mutex_lock_count_map) + list(info.func_spin_lock_count_map)):

		# find all callee functions with locks
		ad = addr
		while ad <= get_enclosing_func_end_addr(addr) and ad != -1:
			#print(hex(ad))

			if ad in info.insnsmap:
				if info.insnsmap[ad].id == X86_INS_CALL:
					if info.callinsnmap[ad] != -1 and info.callinsnmap[ad] not in info.whitelist and ad in info.lockset:
						#print(hex(ad))
						#print("[", end='')
						#for l in info.lockset[ad]:
						#	print(hex(l) + " ", end='')
						#print("]")
						if info.callinsnmap[ad] not in info.callee_root_function_to_lockset_map:
							info.callee_root_function_to_lockset_map[info.callinsnmap[ad]] = info.lockset[ad]
						else:
							info.callee_root_function_to_lockset_map[info.callinsnmap[ad]] = \
								info.callee_root_function_to_lockset_map[info.callinsnmap[ad]].union(info.lockset[ad])
						if info.callinsnmap[ad] not in info.callee_root_function_to_caller_map:
							s = set()
							s.add(get_enclosing_func_addr(ad))
							info.callee_root_function_to_caller_map[info.callinsnmap[ad]] = s
						else:
							s = set()
							s.add(get_enclosing_func_addr(ad))
							info.callee_root_function_to_caller_map[info.callinsnmap[ad]] = \
								info.callee_root_function_to_caller_map[info.callinsnmap[ad]].union(s)
						if info.callinsnmap[ad] not in info.callee_root_function_to_callsite_map:
							s = set()
							s.add(ad)
							info.callee_root_function_to_callsite_map[info.callinsnmap[ad]] = s
						else:
							s = set()
							s.add(ad)
							info.callee_root_function_to_callsite_map[info.callinsnmap[ad]] = \
								info.callee_root_function_to_callsite_map[info.callinsnmap[ad]].union(s)


				elif info.insnsmap[ad].id == X86_INS_JMP:
					if info.jmpinsnmap[ad][0] != -1 and info.jmpinsnmap[ad][0] not in info.whitelist and ad in info.lockset:
						if info.jmpinsnmap[ad][0] < get_enclosing_func_addr(ad) or info.jmpinsnmap[ad][0] > get_enclosing_func_end_addr(ad):
							#print(hex(ad))
							#print("[", end='')
							#for l in info.lockset[ad]:
							#	print(hex(l) + " ", end='')
							#print("]")
							if info.jmpinsnmap[ad][0] not in info.callee_root_function_to_lockset_map:
								info.callee_root_function_to_lockset_map[info.jmpinsnmap[ad][0]] = info.lockset[ad]
							else:
								info.callee_root_function_to_lockset_map[info.jmpinsnmap[ad][0]] = \
									info.callee_root_function_to_lockset_map[info.jmpinsnmap[ad][0]].union(info.lockset[ad])
							if info.jmpinsnmap[ad][0] not in info.callee_root_function_to_caller_map:
								s = set()
								s.add(get_enclosing_func_addr(ad))
								info.callee_root_function_to_caller_map[info.jmpinsnmap[ad][0]] = set(s)
							else:
								s = set()
								s.add(get_enclosing_func_addr(ad))
								info.callee_root_function_to_caller_map[info.jmpinsnmap[ad][0]] = \
									info.callee_root_function_to_caller_map[info.jmpinsnmap[ad][0]].union(s)
							if info.jmpinsnmap[ad][0] not in info.callee_root_function_to_callsite_map:
								s = set()
								s.add(ad)
								info.callee_root_function_to_callsite_map[info.jmpinsnmap[ad][0]] = s
							else:
								s = set()
								s.add(ad)
								info.callee_root_function_to_callsite_map[info.jmpinsnmap[ad][0]] = \
									info.callee_root_function_to_callsite_map[info.jmpinsnmap[ad][0]].union(s)
			ad = findnextinsaddr(ad)


	#for addr in sorted(info.callee_root_function_to_lockset_map):
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for l in info.callee_root_function_to_lockset_map[addr]:
	#		print(hex(l) + " ", end='')
	#	print("]")


	#for addr in sorted(info.callee_root_function_to_caller_map):
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for f in info.callee_root_function_to_caller_map[addr]:
	#		print(hex(f) + " ", end='')
	#	print("]")

	#for addr in sorted(info.callee_root_function_to_callsite_map):
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for callsite in info.callee_root_function_to_callsite_map[addr]:
	#		print(hex(callsite) + " ", end='')
	#	print("]")


	# inter-procedural step 2
	# for each callee, find all callees recursively
	for addr in sorted(info.callee_root_function_to_lockset_map):
		worklist = [addr]
		visited = []

		while worklist:
			func_addr = worklist.pop(0)
			#print("*")
			#print(hex(func_addr))
			#print(hex(get_enclosing_func_end_addr(func_addr)))				
			#print("**")
			insn = func_addr
			while insn <= get_enclosing_func_end_addr(func_addr) and insn != -1:
				#print(hex(insn))

				if insn in info.insnsmap:
					if info.insnsmap[insn].id == X86_INS_CALL:
						if info.callinsnmap[insn] != -1 and info.callinsnmap[insn] not in info.whitelist:
							if info.callinsnmap[insn] not in visited:
								worklist.append(info.callinsnmap[insn])
								visited.append(info.callinsnmap[insn])
								#print("+++++")
								#print(visited)
								#print(hex(info.callinsnmap[insn]))
					elif info.insnsmap[insn].id == X86_INS_JMP:
						if info.jmpinsnmap[insn][0] != -1 and info.jmpinsnmap[insn][0] not in info.whitelist:
							if info.jmpinsnmap[insn][0] < get_enclosing_func_addr(insn) or info.jmpinsnmap[insn][0] > get_enclosing_func_end_addr(insn):
								if info.jmpinsnmap[insn][0] not in visited:
									worklist.append(info.jmpinsnmap[insn][0])
									visited.append(info.jmpinsnmap[insn][0])
									#print("xxxxx")
									#print(visited)
									#print(hex(info.jmpinsnmap[insn][0]))
				insn = findnextinsaddr(insn)

		info.callee_root_function_to_functions_map[addr] = visited

		#print(hex(addr))
		#print(visited)

	#for addr in sorted(info.callee_root_function_to_functions_map):
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for l in info.callee_root_function_to_lockset_map[addr]:
	#		print(hex(l) + " ", end='')
	#	print("]")
	#	print("[", end='')
	#	for f in info.callee_root_function_to_caller_map[addr]:
	#		print(hex(f) + " ", end='')
	#	print("]")
	#	print("[", end='')
	#	for f in info.callee_root_function_to_functions_map[addr]:
	#		print(hex(f) + " ", end='')
	#	print("]")


	# inter-procedural step 3

	funcs = set()

	for addr in sorted(info.callee_root_function_to_functions_map):
		funcs.add(addr)
		funcs = funcs.union(info.callee_root_function_to_caller_map[addr])
		funcs = funcs.union(set(info.callee_root_function_to_functions_map[addr]))

	#print(funcs)
	#for func in funcs:
	#	print(hex(func))

	while True:
		old_d = copy.deepcopy(info.lockset)

		# propagate locksets to callees
		for addr in sorted(info.callee_root_function_to_functions_map):
			update_funcs = []
			update_funcs.extend(info.callee_root_function_to_functions_map[addr])
			update_funcs.append(addr)
			#print("*")
			#print(hex(addr))
			#for update_func in update_funcs:
			#	print(hex(update_func))

			#print("*****")
			#print("[", end='')
			#for l in info.callee_root_function_to_lockset_map[addr]:
			#	print(hex(l) + " ", end='')
			#print("]")

			for update_func in update_funcs:
				#print("*")
				#print(hex(update_func))

				ad = update_func
				while ad <= get_enclosing_func_end_addr(update_func) and ad != -1:
					if ad in info.lockset:
						#print(hex(ad))
						#print("[", end='')
						#for l in info.lockset[ad]:
						#	print(hex(l) + " ", end='')
						#print("]")
						info.lockset[ad] = info.lockset[ad].union(info.callee_root_function_to_lockset_map[addr])
					else:
						info.lockset[ad] = copy.deepcopy(info.callee_root_function_to_lockset_map[addr])
					ad = findnextinsaddr(ad)	


		# update info.callee_root_function_to_lockset_map
		for func in sorted(info.callee_root_function_to_callsite_map):
			#print("*")
			#print(hex(func))
			for callsite in sorted(info.callee_root_function_to_callsite_map[func]):
				#print(hex(callsite))
				#if callsite in info.lockset:
				#	print("[", end='')
				#	for l in info.lockset[callsite]:
				#		print(hex(l) + " ", end='')
				#	print("]")
				if callsite in info.lockset:
					if func in info.callee_root_function_to_lockset_map:
						info.callee_root_function_to_lockset_map[func] = \
							info.callee_root_function_to_lockset_map[func].union(info.lockset[callsite])
					else:
						info.callee_root_function_to_lockset_map[func] = info.lockset[callsite]

		# update callee_root_function list
		# including:
		# info.callee_root_function_to_lockset_map
		# info.callee_root_function_to_caller_map
		# info.callee_root_function_to_callsite_map
		# info.callee_root_function_to_functions_map


		changed = False
		for func in funcs:
			if check_lock_set_changed(old_d, info.lockset, func, get_enclosing_func_end_addr(func)):
				changed = True
		if changed == False:
			break

		#print("+")




	# normalize lockset
	for addr in sorted(info.lockset):
		#print("*")
		#print(hex(addr))
		if -1 in info.lockset[addr]:
			#print("[", end='')
			#for l in info.lockset[addr]:
			#	print(hex(l) + " ", end='')
			#print("]")
			s = set()
			s.add(-1)
			info.lockset[addr] = s

		#print("[", end='')
		#for l in info.lockset[addr]:
		#	print(hex(l) + " ", end='')
		#print("]")


	#print("+++++")
	#for addr in sorted(info.lockset):
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for l in info.lockset[addr]:
	#		print(hex(l) + " ", end='')
	#	print("]")



	# save intermediate results in tmp file
	f = open(info.locksetfile, "w")
	for addr in sorted(info.lockset):
		f.write("*\n")
		f.write(hex(addr) + "\n")
		f.write("[")
		for l in info.lockset[addr]:
			f.write(hex(l) + " ")
		f.write("]" + "\n")

	f.close()


def lockset_analysis():

	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("lockset_analysis\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("lockset_analysis")


	#print("lockset_analysis")
	#for gv_addr in sorted(info.gv_reverse_map):
	#	print("*\n")
	#	print(hex(gv_addr))
	#	print("[")
	#	for l in info.gv_reverse_map[gv_addr]:
	#		print(hex(l[0]) + " ", end='')
	#		print(hex(l[1]) + " ", end='')
	#	print("]")

	potential_race_gv_set = set()
	for gv_addr in sorted(info.gv_reverse_map):
		for l in info.gv_reverse_map[gv_addr]:
			if l[1] == 2 or l[1] == 3:
				potential_race_gv_set.add(gv_addr)

	#print("potential_race_gv_set: " + str(potential_race_gv_set))
	#for gv_addr in sorted(potential_race_gv_set):
	#	print(hex(gv_addr))

	#for addr in sorted(info.ots_once_caller_callee_map):
	#	print(hex(addr))
	#	for callee in sorted(info.ots_once_caller_callee_map[addr]):
	#		print(hex(callee))

	potential_interleavings = 0
	potential_pairs = 0

	for gv_addr in sorted(potential_race_gv_set):
		for access1 in info.gv_reverse_map[gv_addr]:
			for access2 in info.gv_reverse_map[gv_addr]:
				access1_addr = access1[0]
				access2_addr = access2[0]
				access1_type = access1[1]
				access2_type = access2[1]
				potential_interleavings = potential_interleavings + 1

				if access1_type > 1 or access2_type > 1:
					if access1_addr in info.lockset and -3 in info.lockset[access1_addr]:
						continue
					if access2_addr in info.lockset and -3 in info.lockset[access2_addr]:
						continue

					access1_func_addr = get_enclosing_func_addr_1(access1_addr)
					access2_func_addr = get_enclosing_func_addr_1(access2_addr)

					#access1_func_callees = set()
					#access2_func_callees = set()

					#if access1_func_addr in info.callgraph:
					#	for node in info.callgraph[access1_func_addr]:
					#		access1_func_callees.add(node[1])
					#	if access2_func_addr in access1_func_callees and access2_addr in info.lockset and -2 in info.lockset[access2_addr]:
					#		continue

					#if access2_func_addr in info.callgraph:
					#	for node in info.callgraph[access2_func_addr]:
					#		access2_func_callees.add(node[1])
					#	if access1_func_addr in access2_func_callees and access1_addr in info.lockset and -2 in info.lockset[access1_addr]:
					#		continue

					if access1_func_addr in info.ots_once_caller_callee_map:
						if access2_func_addr in info.ots_once_caller_callee_map[access1_func_addr] and -2 in info.lockset[access2_addr]:
							#print("if access1_func_addr in info.ots_once_caller_callee_map:")
							#print(hex(access1_addr))
							#print(hex(access2_addr))
							continue

					if access2_func_addr in info.ots_once_caller_callee_map:
						if access1_func_addr in info.ots_once_caller_callee_map[access2_func_addr] and -2 in info.lockset[access1_addr]:
							#print("if access2_func_addr in info.ots_once_caller_callee_map:")
							#print(hex(access1_addr))
							#print(hex(access2_addr))
							continue

					if access1_addr in info.lockset and -2 in info.lockset[access1_addr] and access2_addr in info.lockset and  -2 in info.lockset[access2_addr]:
						continue
						

					if access1_addr not in info.lockset or access2_addr not in info.lockset:
						# found a race
						info.race_sites_list.append([[gv_addr, access1_addr, access1_type],[gv_addr, access2_addr, access2_type], 0])
					else:
						access1_lockset = info.lockset[access1_addr]
						access2_lockset = info.lockset[access2_addr]

						if -1 not in access1_lockset and -1 not in access2_lockset:
							if len(access1_lockset.intersection(access2_lockset)) == 0:
								# found a race
								info.race_sites_list.append([[gv_addr, access1_addr, access1_type],[gv_addr, access2_addr, access2_type], 0])
		n = len(info.gv_reverse_map[gv_addr])
		potential_pairs = potential_pairs + int(n*(n + 1)/2)
		#print("*")
		#print(n)
		#print(int(n*(n + 1)/2))


	#print("info.race_sites_list: " + str(info.race_sites_list))
	print("potential racing pairs: " + str(potential_pairs))
	print("potential racing interleavings: " + str(potential_interleavings))

	# eliminate redundant racing pairs
	# for instance, [accessA, accessB] and [accessB, accessA] are the same and one gets eliminated here
	remove_index_list = []
	unremove_index_list = []

	for race_sites in info.race_sites_list:
		if [[race_sites[1][0], race_sites[1][1], race_sites[1][2]], [race_sites[0][0], race_sites[0][1], race_sites[0][2]], 0] in info.race_sites_list:
			index = info.race_sites_list.index(race_sites)
			mirrorindex = info.race_sites_list.index([[race_sites[1][0], race_sites[1][1], race_sites[1][2]], [race_sites[0][0], race_sites[0][1], race_sites[0][2]], 0])
			if index != mirrorindex:
				# we are gonna remove one of them
				if mirrorindex not in unremove_index_list:
					remove_index_list.append(mirrorindex)
				unremove_index_list.append(index)

	templist = []
	for race_sites in info.race_sites_list:
		if info.race_sites_list.index(race_sites) not in remove_index_list:
			templist.append(race_sites)

	info.race_sites_list = templist


	for race_sites in info.race_sites_list:
		if race_sites[0][0] not in info.race_sites_map:
			info.race_sites_map[race_sites[0][0]] = [race_sites]
		else:
			info.race_sites_map[race_sites[0][0]].append(race_sites)

	# step 2: check lock acquisition history

	# get all unique locks
	all_locks = set()
	for addr in sorted(info.lockset):
		#print("*")
		#print(hex(addr))
		#print("[", end='')
		for l in info.lockset[addr]:
			#print(hex(l) + " ", end='')
			if l != -0x1:
				all_locks.add(l)
		#print("]")

	#for l in sorted(all_locks):
	#	print(hex(l))

	for addr in sorted(info.lockset):
		info.lockhistory[addr] = {}
		locks = set()
		if -0x1 in info.lockset[addr]:
			locks = copy.deepcopy(all_locks)
		else:
			locks = copy.deepcopy(info.lockset[addr])

		for lock in sorted(locks):
			tmpset = copy.deepcopy(locks)
			tmpset.remove(lock)
			info.lockhistory[addr][lock] = tmpset

	#for addr in sorted(info.lockhistory):
	#	print("*")
	#	print(hex(addr))
	#	for lock_addr in sorted(info.lockhistory[addr]):
	#		print("lock history for lock " + hex(lock_addr) + ":")
	#		print("[", end='')
	#		for l in info.lockhistory[addr][lock_addr]:
	#			print(hex(l) + " ", end='')
	#		print("]")

	remove_set = set()

	for gv_addr in info.race_sites_map:
		for race_sites in info.race_sites_map[gv_addr]:
			#print("*")
			#print("access1:")
			#print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
			#print("access2:")
			#print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))
			if race_sites[0][1] in info.lockhistory and race_sites[1][1] in info.lockhistory:
				locks1 = set(sorted(info.lockhistory[race_sites[0][1]]))
				locks2 = set(sorted(info.lockhistory[race_sites[1][1]]))
				interlocks = locks1.intersection(locks2)
				if len(locks1) >= 1 and len(locks2) >= 1:
					#print("*")
					#print("access1:")
					#print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
					#print("access2:")
					#print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))
					for lock1 in sorted(locks1):
						for lock2 in sorted(locks2):
							if lock1 in info.lockhistory[race_sites[1][1]][lock2] and lock2 in info.lockhistory[race_sites[0][1]][lock1]:
								#print("*")
								#print("access1:")
								#print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
								#print("access2:")
								#print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))
								tmpsites = copy.deepcopy(race_sites)
								remove_set.add(tmpsites)

	# remove racing pairs failed to lock history test
	#print(len(remove_set))
	remove_index_set = set()
	index = 0
	for race_sites in info.race_sites_list:
		for remove_sites in remove_set:
			if race_sites[0][0] == remove_sites[0][0]:
				if race_sites[0][1] == remove_sites[0][1] and race_sites[1][1] == remove_sites[1][1]:
					if race_sites[0][2] == remove_sites[0][2] and race_sites[1][2] == remove_sites[1][2]:
						remove_index_set.add(index)
		index = index + 1

	#print(len(remove_index_set))
	#print(len(info.race_sites_list))

	templist = []
	index = 0
	for race_sites in info.race_sites_list:
		if index not in remove_index_set:
			templist.append(race_sites)
		index = index + 1

	info.race_sites_list = templist

	#print(len(info.race_sites_list))


	info.race_sites_map = {}

	for race_sites in info.race_sites_list:
		if race_sites[0][0] not in info.race_sites_map:
			info.race_sites_map[race_sites[0][0]] = [race_sites]
		else:
			info.race_sites_map[race_sites[0][0]].append(race_sites)

	#print(len(info.race_sites_list))



	# output lockset analysis results

	#for race_sites in info.race_sites_list:
	#	print("*")
	#	print("access1:")
	#	print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
	#	print("access2:")
	#	print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

	#if info.args.output:
	#	info.outputfile = open(os.path.realpath(info.args.output), "w") 
	#	for race_sites in info.race_sites_list:
	#		info.outputfile.write("*\n")
	#		info.outputfile.write("access1:\n")
	#		info.outputfile.write(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]) + "\n")
	#		info.outputfile.write("access2:\n")
	#		info.outputfile.write(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]) + "\n")
	#	info.outputfile.close()

	#for gv_addr in info.race_sites_map:
	#	for race_sites in info.race_sites_map[gv_addr]:
	#		print("*")
	#		print("access1:")
	#		print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
	#		print("access2:")
	#		print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))


def exploitable_analysis():

	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("exploitable_analysis\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("exploitable_analysis")

	#print("exploitable_analysis")


	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("step 1. data flow violation\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("step 1. data flow violation")

	#print("step 1. data flow violation")
	# step 1. data flow violation

	violation_gv_set = set(info.race_sites_map.keys())

	# check whether a global variable remains a constant
	for gv_addr in sorted(info.race_sites_map):
		#print("*")
		#print(hex(gv_addr))
		#for race_sites in info.race_sites_map[gv_addr]:
		#	print("access1:")
		#	print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
		#	print("access2:")
		#	print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

		constant_flag = True
		constant_set = set()

		# find all accesses of that variable
		for l in info.gv_reverse_map[gv_addr]:
			# not read access
			if l[1] != 1:
				#print(hex(l[0]))

				# backwards slice to determine whether it is constant

				resolve_start = -1
				resolve_end = -1

				if get_enclosing_bb_addr(l[0]) != -1:
					resolve_start = get_enclosing_bb_addr(l[0])

				if findnextinsaddr(l[0]) != -1:
					resolve_end = findnextinsaddr(l[0])
				else:
					resolve_end = l[0]

				if resolve_start != -1:

					visitmap = {}
					addr = resolve_start
					while addr <= resolve_end and addr != -1:
						visitmap[addr] = 0
						addr = findnextinsaddr(addr)

					info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

					makeregistersymbolic("init_")
					info.state.regs.rsp = initial_rsp = info.state.solver.BVS("rsp", 64)
					info.state.regs.rbp = info.state.solver.BVS("rbp", 64)

					info.states = [info.state]

					while True:
						if not info.states:
							break

						info.state = info.states.pop(0)

						if info.state.addr < resolve_start or info.state.addr > resolve_end:
							break

						if not info.state.addr in visitmap or visitmap[info.state.addr] != 0:
							break

						#print(hex(info.state.addr))


						visitmap[info.state.addr] = 1
						info.succs = []
						#print(hex(info.state.addr))
						try:
							info.succs = info.project.factory.successors(info.state, num_inst=1).successors
							info.states.extend(info.succs)
						except:
							pass
					#gc.collect()

					#print(info.state.regs.rdi)
					#print(info.state.regs.rdi.symbolic)
					#print(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE).__class__)
					#print(dir(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE)))
					#print("*")
					#print(hex(addr))
					#print(hex(info.state.mem[gv_addr].uint64_t.resolved))

					#if not info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE).symbolic:
						#print(info.state.memory.load(gv_addr, 8, endness=archinfo.Endness.LE))
						#print(info.insnsmap[l[0]].mnemonic)
						#print(info.insnsmap[l[0]].id)
						#print(info.insnsmap[l[0]].op_str)

					memory_access_width = 0
					if "xmmword" in info.insnsmap[l[0]].op_str:
						memory_access_width = 16
					elif "qword" in info.insnsmap[l[0]].op_str:
						memory_access_width = 8
					elif "dword" in info.insnsmap[l[0]].op_str:
						memory_access_width = 4
					elif "word" in info.insnsmap[l[0]].op_str:
						memory_access_width = 2
					elif "byte" in info.insnsmap[l[0]].op_str:
						memory_access_width = 1
					else:
						constant_flag = False
						break

					# add binary specified value to constant_set
					if v_dyn_addr_to_binary_offset(gv_addr) != -1:
						constant_set.add(read_variable_initial_value_in_binary(gv_addr, memory_access_width))
						#print("*")
						#print(hex(gv_addr))
						#print(hex(read_variable_initial_value_in_binary(gv_addr, memory_access_width)))

					if not info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE).symbolic:
						#print("+")
						#print(info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE))
						#print(info.state.solver.eval(info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE)))
						constant = info.state.solver.eval(info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE))

						# record the constant write
						info.constantwritemap[l[0]] = [gv_addr,constant]

						if constant not in constant_set and constant_set:
							#print("*")
							#print(hex(gv_addr))
							#print(hex(constant))
							#for constant_value in sorted(constant_set):
							#	print(hex(constant_value))

							constant_flag = False
						else:
							constant_set.add(constant)
					else:
						constant_flag = False

		#print(constant_flag)
		if constant_flag:
			violation_gv_set.remove(gv_addr)

	#for gv_addr in sorted(violation_gv_set):
	#	print(hex(gv_addr))

	#for cons_write_addr in sorted(info.constantwritemap):
	#	print("*")
	#	print(hex(cons_write_addr))
	#	print(hex(info.constantwritemap[cons_write_addr][0]))
	#	print(hex(info.constantwritemap[cons_write_addr][1]))		


	# update data race info
	for race_sites in info.race_sites_list:
		if race_sites[0][0] in violation_gv_set:
			if race_sites[0][1] in info.constantwritemap and race_sites[1][1] in info.constantwritemap:
				#print("*")
				#print(hex(race_sites[0][0]))
				#print(hex(race_sites[0][1]))
				#print(hex(race_sites[1][1]))
				constant1 = info.constantwritemap[race_sites[0][1]][1]
				constant2 = info.constantwritemap[race_sites[1][1]][1]
				if constant1 == constant2:
					race_sites[2] = 0
					#print("*")
					#print(hex(race_sites[0][1]))
					#print(hex(race_sites[1][1]))
					#print(hex(constant1))
				else:
					race_sites[2] = 1
			else:
				race_sites[2] = 1
		else:
			race_sites[2] = 0

	for gv_addr in info.race_sites_map:
		if gv_addr in violation_gv_set:
			for race_sites in info.race_sites_map[gv_addr]:
				# (check whether racing accesses have the same value)
				if race_sites[0][1] in info.constantwritemap and race_sites[1][1] in info.constantwritemap:
					constant1 = info.constantwritemap[race_sites[0][1]][1]
					constant2 = info.constantwritemap[race_sites[1][1]][1]
					if constant1 == constant2:
						race_sites[2] = 0
						#print("*")
						#print(hex(race_sites[0][1]))
						#print(hex(race_sites[1][1]))
						#print(hex(constant1))
					else:
						race_sites[2] = 1
				else:
					race_sites[2] = 1
		else:
			for race_sites in info.race_sites_map[gv_addr]:
				race_sites[2] = 0


	if info.args.output2:
		info.outputfile2 = open(os.path.realpath(info.args.output2), "a") 
		info.outputfile2.write("step 2. control flow bending\n")
		info.outputfile2.flush()
		info.outputfile2.close()
		print("step 2. control flow bending")

	#print("step 2. control flow bending")
	# step 2. control flow bending
	# check whether one racing access could change control flow

	# access address set
	bending_access_set = set()

	for gv_addr in sorted(info.race_sites_map):
		if gv_addr in violation_gv_set:
			#print("*")
			#print(hex(gv_addr))

			check_access_set = set()
			gv_bending_access_set = set()
			for race_sites in info.race_sites_map[gv_addr]:
				#print("access1:")
				#print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
				#print("access2:")
				#print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

				# (check whether racing accesses have the same value)
				if race_sites[0][1] in info.constantwritemap and race_sites[1][1] in info.constantwritemap:
					constant1 = info.constantwritemap[race_sites[0][1]][1]
					constant2 = info.constantwritemap[race_sites[1][1]][1]
					if constant1 == constant2:
						continue


				if race_sites[0][2] != 1:
					check_access_set.add(race_sites[1][1])
					#print("+")
					#print(hex(race_sites[1][1]) + "*")
					#print(hex(race_sites[0][1]))
				if race_sites[1][2] != 1:
					check_access_set.add(race_sites[0][1])
					#print("+")
					#print(hex(race_sites[0][1]) + "*")
					#print(hex(race_sites[1][1]))

			#print("check_access_set:")
			#for addr in sorted(check_access_set):
			#	print(hex(addr))

			#print("*")
			#print(hex(gv_addr))


			#print("check control flow bending within one basic block")
			# check control flow bending within one basic block
			for addr in check_access_set:
				#print("+")
				#print(hex(addr))
				#print(hex(get_enclosing_bb_end_addr(addr)))
				resolve_start = 0
				if get_enclosing_bb_addr(addr) != -0x1:
					resolve_start = get_enclosing_bb_addr(addr)
				else:
					resolve_start = addr
				resolve_end = get_enclosing_bb_end_addr(addr)
				testcmp_addr = 0

				if resolve_end != -1:

					# first check whether there is a test or cmp instruction within reach
					ad = resolve_start
					while ad <= resolve_end:
						if ad in info.insnsmap:
							if info.insnsmap[ad].id == X86_INS_TEST or (info.insnsmap[ad].id >= X86_INS_CMP and info.insnsmap[ad].id <= X86_INS_CMPXCHG8B):
								#resolve_end = ad
								if findnextinsaddr(ad) == -0x1:
									#print("CMPTESTNONEXT_" + hex(ad))
									resolve_end = ad
								else:
									resolve_end = findnextinsaddr(ad)
								testcmp_addr = ad
								break
						ad = findnextinsaddr(ad)
						if ad == -1:
							#print("ITERATENONEXT_" + hex(ad))
							break

					if testcmp_addr == 0:
						continue


					#print("+")
					#print(hex(addr))
					#print(hex(testcmp_addr))
					#print(hex(resolve_start))
					#print(hex(resolve_end))


					# a simple taint analysis
					memory_access_width = 0
					if "xmmword" in info.insnsmap[addr].op_str:
						memory_access_width = 16
					elif "qword" in info.insnsmap[addr].op_str:
						memory_access_width = 8
					elif "dword" in info.insnsmap[addr].op_str:
						memory_access_width = 4
					elif "word" in info.insnsmap[addr].op_str:
						memory_access_width = 2
					elif "byte" in info.insnsmap[addr].op_str:
						memory_access_width = 1
					else:
						continue

					#print("memory_access_width:")
					#print(hex(memory_access_width))


					visitmap = {}
					addr = resolve_start
					while addr <= resolve_end and addr != -1:
						visitmap[addr] = 0
						addr = findnextinsaddr(addr)


					info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})


					###random_value = random.randint(1, pow(2, 8 * memory_access_width) - 2)
					#print("random_value:")
					#print(hex(random_value))

					###info.state.memory.store(gv_addr, random_value, memory_access_width, endness=archinfo.Endness.LE)
					#print(info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE))


					info.state.memory.store(gv_addr, info.state.solver.BVS("corrupted", 8 * memory_access_width), memory_access_width, endness=archinfo.Endness.LE)
					#print(info.state.memory.load(gv_addr, memory_access_width, endness=archinfo.Endness.LE))

					#print("*")

					makeregistersymbolic("init_")
					info.state.regs.rbp = info.state.regs.rsp = initial_rsp = 0x7fffffff

					info.states = [info.state]

					exe_except_flag = False

					while True:
						if not info.states:
							break

						info.state = info.states.pop(0)

						#print("exploitable_analysis: control")
						#print(hex(info.state.addr))

						#print(info.state.registers.load("eax"))

						if info.state.addr < resolve_start or info.state.addr > resolve_end:
							exe_except_flag = True
							break

						if not info.state.addr in visitmap or visitmap[info.state.addr] != 0:
							exe_except_flag = True
							break


						if info.state.addr == resolve_end:
							#print("exe finish at: " + hex(info.state.addr))
							break

						#print(hex(info.state.addr))
						#print(info.state.registers.load("eax"))

						visitmap[info.state.addr] = 1
						info.succs = []
						try:
							info.succs = info.project.factory.successors(info.state, num_inst=1).successors
						except:
							#print("---EXE EXCEPTION---")
							#print(hex(info.state.addr))
							#print(hex(findnextinsaddr(info.state.addr)))
							if findnextinsaddr(info.state.addr) != -0x1:
								info.state = info.project.factory.entry_state(addr=findnextinsaddr(info.state.addr), \
										 add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})
								info.state.memory.store(gv_addr, info.state.solver.BVS("corrupted", 8 * memory_access_width), \
												 memory_access_width, endness=archinfo.Endness.LE)
								makeregistersymbolic("init_")
								info.state.regs.rbp = info.state.regs.rsp = initial_rsp = 0x7fffffff
								info.succs = [info.state]
							else:
								exe_except_flag = True
								break
							
						info.states.extend(info.succs)

					if exe_except_flag == True:
						continue

					#print("*")
					#print(hex(info.state.addr))


					# examine the state (it coule be the program point after the testcmpinst or before(if no afterwards insn(very rare)))
					if testcmp_addr not in info.insnsmap:
						continue
					testcmp_capstone_insn = info.insnsmap[testcmp_addr]

					if len(testcmp_capstone_insn.operands) != 2:
						continue
					else:

						bend_flag = False
						base = 0
						index = 0
						scale = 0
						disp = 0
						branch_var_addr = 0



						if testcmp_capstone_insn.operands[0].type == X86_OP_MEM:
							#print("operands[0].type == X86_OP_MEM")
							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.base))
							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.base)))

							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.base)).symbolic)

							if not info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.base)).symbolic:
								base = info.state.solver.eval( \
									info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.base)))
								#print(hex(base))

							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.index))
							#if not testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.index):
							#	print("it's none.")
							if testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.index):
								if not info.state.registers.load( \
									testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.index)).symbolic:
									index = info.state.solver.eval( \
										info.state.registers.load( \
										testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.mem.index)))
									#print(hex(index))

							#print(hex(testcmp_capstone_insn.operands[0].value.mem.scale))
							scale = testcmp_capstone_insn.operands[0].value.mem.scale
							#print(hex(testcmp_capstone_insn.operands[0].value.mem.disp))
							disp = testcmp_capstone_insn.operands[0].value.mem.disp

							#print("address: " + hex(base + index * scale + disp))
							branch_var_addr = base + index * scale + disp


							memory_access_width = 8
							if "xmmword" in testcmp_capstone_insn.op_str:
								memory_access_width = 16
							elif "qword" in testcmp_capstone_insn.op_str:
								memory_access_width = 8
							elif "dword" in testcmp_capstone_insn.op_str:
								memory_access_width = 4
							elif "word" in testcmp_capstone_insn.op_str:
								memory_access_width = 2
							elif "byte" in testcmp_capstone_insn.op_str:
								memory_access_width = 1

							#print("memory_access_width:")
							#print(hex(memory_access_width))

							#print(info.state.memory.load(branch_var_addr, memory_access_width, endness=archinfo.Endness.LE))

							# quick check
							# check AST
							try:
								if "corrupted" in str(info.state.memory.load(branch_var_addr, memory_access_width, endness=archinfo.Endness.LE)):
									gv_bending_access_set.add(addr)
									#print("corrupted at testcmp_capstone_insn.operands[0] MEM")
									#print(hex(addr))
							except:
								pass




						elif testcmp_capstone_insn.operands[0].type == X86_OP_REG:
							#print("operands[0].type == X86_OP_REG")
							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.reg))
							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.reg)))

							# quick check
							# check AST
							try:
								if "corrupted" in str(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[0].value.reg))):
									gv_bending_access_set.add(addr)
									#print(hex(addr))
							except:
								pass
							
						#elif testcmp_capstone_insn.operands[0].type == X86_OP_IMM:
						#	print("operands[0].type == X86_OP_IMM")
						#else:
						#	continue
						if testcmp_capstone_insn.operands[1].type == X86_OP_MEM:
							#print("operands[1].type == X86_OP_MEM")
							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.base))
							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.base)))

							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.base)).symbolic)
							try:
								if not info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.base)).symbolic:
									base = info.state.solver.eval( \
										info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.base)))
									#print(hex(base))
							except:
								continue

							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.index))
							#if not testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.index):
							#	print("it's none.")
							if testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.index):
								if not info.state.registers.load( \
									testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.index)).symbolic:
									index = info.state.solver.eval( \
										info.state.registers.load( \
										testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.mem.index)))
									#print(hex(index))

							#print(hex(testcmp_capstone_insn.operands[1].value.mem.scale))
							scale = testcmp_capstone_insn.operands[1].value.mem.scale
							#print(hex(testcmp_capstone_insn.operands[1].value.mem.disp))
							disp = testcmp_capstone_insn.operands[1].value.mem.disp

							#print("address: " + hex(base + index * scale + disp))
							branch_var_addr = base + index * scale + disp


							memory_access_width = 8
							if "xmmword" in testcmp_capstone_insn.op_str:
								memory_access_width = 16
							elif "qword" in testcmp_capstone_insn.op_str:
								memory_access_width = 8
							elif "dword" in testcmp_capstone_insn.op_str:
								memory_access_width = 4
							elif "word" in testcmp_capstone_insn.op_str:
								memory_access_width = 2
							elif "byte" in testcmp_capstone_insn.op_str:
								memory_access_width = 1

							#print("memory_access_width:")
							#print(hex(memory_access_width))

							#print(info.state.memory.load(branch_var_addr, memory_access_width, endness=archinfo.Endness.LE))

							# quick check
							# check AST
							try:
								if "corrupted" in str(info.state.memory.load(branch_var_addr, memory_access_width, endness=archinfo.Endness.LE)):
									gv_bending_access_set.add(addr)
									#print(hex(addr))
							except:
								pass

						elif testcmp_capstone_insn.operands[1].type == X86_OP_REG:
							#print("operands[1].type == X86_OP_REG")
							#print(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.reg))
							#print(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.reg)))

							# quick check
							# check AST
							try:
								if "corrupted" in str(info.state.registers.load(testcmp_capstone_insn.reg_name(testcmp_capstone_insn.operands[1].value.reg))):
									gv_bending_access_set.add(addr)
									#print(hex(addr))
							except:
								pass

						#elif testcmp_capstone_insn.operands[1].type == X86_OP_IMM:
						#	print("operands[1].type == X86_OP_IMM")
						#else:
						#	continue

			#print("gv_bending_access_set:")
			#print("[", end='')
			#for bend_access_addr in sorted(gv_bending_access_set):
			#	print(hex(bend_access_addr) + " ", end='')
			#print("]")

			for race_sites in info.race_sites_map[gv_addr]:
				#print("access1:")
				#print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
				#print("access2:")
				#print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

				control_flag = False

				if race_sites[0][2] != 1 and race_sites[1][1] in gv_bending_access_set:
					control_flag = True
				if race_sites[1][2] != 1 and race_sites[0][1] in gv_bending_access_set:
					control_flag = True

				if race_sites[0][1] in info.constantwritemap and race_sites[1][1] in info.constantwritemap:
					constant1 = info.constantwritemap[race_sites[0][1]][1]
					constant2 = info.constantwritemap[race_sites[1][1]][1]
					if constant1 == constant2:
						continue

				if control_flag:
					race_sites[2] = race_sites[2] | 2
					#print("race_sites[2]:")
					#print(hex(race_sites[2]))

	'''
	# exprimental: eliminate races due to atomicity instructions

	# find atomic instructions like lock cmpxchg
	atomic_insn_addresses = set()

	for insn_line_addr in sorted(info.insnlinesmap):
		insn_line = info.insnlinesmap[insn_line_addr]
		if "lock cmpxchg" in insn_line:
			#print(hex(insn_line_addr))
			atomic_insn_addresses.add(insn_line_addr)

	# analyze within one basic block, if used in test or return to a function that uses it in test
	# it could be a once-like self-defined function

	defined_once_root_func_addresses = set()
	check_callee_func_addresses = set()
	check_caller_func_addresses = set()

	for atomic_insn_address in sorted(atomic_insn_addresses):
		resolve_start = atomic_insn_address
		resolve_end = get_enclosing_bb_end_addr_1(atomic_insn_address)
		resolve_start_next = findnextinsaddr(resolve_start)

		#print("*")
		#print(hex(resolve_start))
		#print(hex(resolve_end))
		#print(hex(resolve_start_next))

		used_in_testcmp = False
		used_in_ret = False

		info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

		makeregistersymbolic("init_")
		info.state.regs.rbp = info.state.regs.rsp = initial_rsp = 0x7fffffff

		info.states = [info.state]


		while True:
			if not info.states:
				break

			info.state = info.states.pop(0)

			#print(hex(info.state.addr))
			#print(info.state.registers.load("eax"))

			if info.state.addr == resolve_start_next:
				info.state.registers.store("rax", info.state.solver.BVS("atomic_rax", 64))

			if info.state.addr in info.insnsmap:
				insn = info.insnsmap[info.state.addr]

			if info.state.addr != atomic_insn_address and info.state.addr in info.insnsmap:
				if info.insnsmap[info.state.addr].id == X86_INS_TEST or	(info.insnsmap[info.state.addr].id >= X86_INS_CMP and info.insnsmap[info.state.addr].id <= X86_INS_CMPXCHG8B):
					
					if insn.operands[0].type == X86_OP_MEM:
						base = 0
						index = 0
						if not info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)).symbolic:
							base = info.state.solver.eval( \
								info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
							#print(hex(base))

						#print(insn.reg_name(insn.operands[0].value.mem.index))
						#if not insn.reg_name(insn.operands[0].value.mem.index):
						#	print("it's none.")
						if insn.reg_name(insn.operands[0].value.mem.index):
							if not info.state.registers.load( \
								insn.reg_name(insn.operands[0].value.mem.index)).symbolic:
								index = info.state.solver.eval( \
									info.state.registers.load( \
									insn.reg_name(insn.operands[0].value.mem.index)))
								#print(hex(index))

						#print(hex(insn.operands[0].value.mem.scale))
						scale = insn.operands[0].value.mem.scale
						#print(hex(insn.operands[0].value.mem.disp))
						disp = insn.operands[0].value.mem.disp

						#print("address: " + hex(base + index * scale + disp))
						mem_access_addr = base + index * scale + disp

						if "atomic_rax" in str(info.state.memory.load(mem_access_addr, 8, endness=archinfo.Endness.LE)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					elif insn.operands[0].type == X86_OP_REG:
						#print("*")
						#print(hex(info.state.addr))
						#print("insn.operands[0].type == X86_OP_REG")
						#print(insn.reg_name(insn.operands[0].value.reg))
						#print(str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg))))
						#print(str(info.state.registers.load("rax")))

						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name.endswith("l"):
							reg_name = "r" + reg_name[0] + "x"
						elif reg_name.endswith("x") and len(reg_name) == 2:
							reg_name = "r" + reg_name
						elif reg_name.startswith("e"):
							reg_name = "r" + reg_name[1:]

						#print(reg_name)

						if "atomic_rax" in str(info.state.registers.load(reg_name)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					if insn.operands[1].type == X86_OP_MEM:
						base = 0
						index = 0
						if not info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base)).symbolic:
							base = info.state.solver.eval( \
								info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base)))
							#print(hex(base))

						#print(insn.reg_name(insn.operands[0].value.mem.index))
						#if not insn.reg_name(insn.operands[0].value.mem.index):
						#	print("it's none.")
						if insn.reg_name(insn.operands[1].value.mem.index):
							if not info.state.registers.load( \
								insn.reg_name(insn.operands[1].value.mem.index)).symbolic:
								index = info.state.solver.eval( \
									info.state.registers.load( \
									insn.reg_name(insn.operands[1].value.mem.index)))
								#print(hex(index))

						#print(hex(insn.operands[0].value.mem.scale))
						scale = insn.operands[1].value.mem.scale
						#print(hex(insn.operands[0].value.mem.disp))
						disp = insn.operands[1].value.mem.disp

						#print("address: " + hex(base + index * scale + disp))
						mem_access_addr = base + index * scale + disp

						if "atomic_rax" in str(info.state.memory.load(mem_access_addr, 8, endness=archinfo.Endness.LE)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					elif insn.operands[1].type == X86_OP_REG:
						#print("*")
						#print(hex(info.state.addr))
						#print("insn.operands[1].type == X86_OP_REG")
						#print(insn.reg_name(insn.operands[1].value.reg))
						#print(str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg))))
						#print(str(info.state.registers.load("rax")))

						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name.endswith("l"):
							reg_name = "r" + reg_name[0] + "x"
						elif reg_name.endswith("x") and len(reg_name) == 2:
							reg_name = "r" + reg_name
						elif reg_name.startswith("e"):
							reg_name = "r" + reg_name[1:]

						#print(reg_name)

						if "atomic_rax" in str(info.state.registers.load(reg_name)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))
					break

			if info.state.addr == resolve_end:
				#print("exe finish at: " + hex(info.state.addr))
				#print(info.state.registers.load("eax"))
				if info.state.addr in info.insnsmap:
					if insn.id == X86_INS_RET or insn.id == X86_INS_RETF or insn.id == X86_INS_RETFQ:
						if "atomic_rax" in str(info.state.registers.load("rax")):
							used_in_ret = True
							check_callee_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))
				break

			#print(hex(info.state.addr))
			#print(info.state.registers.load("eax"))

			info.succs = []

			info.succs = info.project.factory.successors(info.state, num_inst=1).successors
				
			info.states.extend(info.succs)

	for check_callee_func_address in sorted(check_callee_func_addresses):
		#print(hex(check_callee_func_address))
		# callee_addr to [[caller_addr, callsite_addr]]
		#self.callgraph_reverse = {}
		if check_callee_func_address in info.callgraph_reverse:
			for l in info.callgraph_reverse[check_callee_func_address]:
				check_caller_func_addresses.add(l[0])

	caller_resolve_start_addresses = set()

	for check_caller_func_address in sorted(check_caller_func_addresses):
		#print(hex(check_caller_func_address))

		# call_insn_addr to call_target_addr map
		# -1 for unsolved target address
		#self.callinsnmap = {}

		check_caller_func_end_address = get_enclosing_func_end_addr_1(check_caller_func_address)
		#print(hex(check_caller_func_end_address))

		index_addr = check_caller_func_address
		while index_addr <= check_caller_func_end_address:
			if index_addr in info.callinsnmap:
				if info.callinsnmap[index_addr] in check_callee_func_addresses:
					caller_resolve_start_addresses.add(index_addr)
			index_addr = findnextinsaddr(index_addr)

	for caller_resolve_start_address in sorted(caller_resolve_start_addresses):
		#print("*")
		#print(hex(caller_resolve_start_address))

		resolve_end = get_enclosing_bb_end_addr_1(caller_resolve_start_address)
		resolve_start_next = findnextinsaddr(caller_resolve_start_address)

		if resolve_start_next > resolve_end:
			continue

		resolve_start = resolve_start_next


		info.state = info.project.factory.entry_state(addr=resolve_start, add_options={angr.options.CONSTRAINT_TRACKING_IN_SOLVER})

		makeregistersymbolic("init_")
		info.state.regs.rbp = info.state.regs.rsp = initial_rsp = 0x7fffffff

		info.state.registers.store("rax", info.state.solver.BVS("atomic_rax", 64))

		info.states = [info.state]


		while True:
			if not info.states:
				break

			info.state = info.states.pop(0)

			#print(hex(info.state.addr))
			#print(info.state.registers.load("rax"))

			if info.state.addr in info.insnsmap:
				insn = info.insnsmap[info.state.addr]

			if info.state.addr in info.insnsmap:
				if info.insnsmap[info.state.addr].id == X86_INS_TEST or	(info.insnsmap[info.state.addr].id >= X86_INS_CMP and info.insnsmap[info.state.addr].id <= X86_INS_CMPXCHG8B):
					#print(hex(info.state.addr))
					if insn.operands[0].type == X86_OP_MEM:
						base = 0
						index = 0
						if not info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)).symbolic:
							base = info.state.solver.eval( \
								info.state.registers.load(insn.reg_name(insn.operands[0].value.mem.base)))
							#print(hex(base))

						#print(insn.reg_name(insn.operands[0].value.mem.index))
						#if not insn.reg_name(insn.operands[0].value.mem.index):
						#	print("it's none.")
						if insn.reg_name(insn.operands[0].value.mem.index):
							if not info.state.registers.load( \
								insn.reg_name(insn.operands[0].value.mem.index)).symbolic:
								index = info.state.solver.eval( \
									info.state.registers.load( \
									insn.reg_name(insn.operands[0].value.mem.index)))
								#print(hex(index))

						#print(hex(insn.operands[0].value.mem.scale))
						scale = insn.operands[0].value.mem.scale
						#print(hex(insn.operands[0].value.mem.disp))
						disp = insn.operands[0].value.mem.disp

						#print("address: " + hex(base + index * scale + disp))
						mem_access_addr = base + index * scale + disp

						if "atomic_rax" in str(info.state.memory.load(mem_access_addr, 8, endness=archinfo.Endness.LE)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					elif insn.operands[0].type == X86_OP_REG:
						#print("*")
						#print(hex(info.state.addr))
						#print("insn.operands[0].type == X86_OP_REG")
						#print(insn.reg_name(insn.operands[0].value.reg))
						#print(str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg))))
						#print(str(info.state.registers.load("rax")))

						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name.endswith("l"):
							reg_name = "r" + reg_name[0] + "x"
						elif reg_name.endswith("x") and len(reg_name) == 2:
							reg_name = "r" + reg_name
						elif reg_name.startswith("e"):
							reg_name = "r" + reg_name[1:]

						#print(reg_name)

						if "atomic_rax" in str(info.state.registers.load(reg_name)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					if insn.operands[1].type == X86_OP_MEM:
						base = 0
						index = 0
						if not info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base)).symbolic:
							base = info.state.solver.eval( \
								info.state.registers.load(insn.reg_name(insn.operands[1].value.mem.base)))
							#print(hex(base))

						#print(insn.reg_name(insn.operands[0].value.mem.index))
						#if not insn.reg_name(insn.operands[0].value.mem.index):
						#	print("it's none.")
						if insn.reg_name(insn.operands[1].value.mem.index):
							if not info.state.registers.load( \
								insn.reg_name(insn.operands[1].value.mem.index)).symbolic:
								index = info.state.solver.eval( \
									info.state.registers.load( \
									insn.reg_name(insn.operands[1].value.mem.index)))
								#print(hex(index))

						#print(hex(insn.operands[0].value.mem.scale))
						scale = insn.operands[1].value.mem.scale
						#print(hex(insn.operands[0].value.mem.disp))
						disp = insn.operands[1].value.mem.disp

						#print("address: " + hex(base + index * scale + disp))
						mem_access_addr = base + index * scale + disp

						if "atomic_rax" in str(info.state.memory.load(mem_access_addr, 8, endness=archinfo.Endness.LE)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					elif insn.operands[1].type == X86_OP_REG:
						#print("*")
						#print(hex(info.state.addr))
						#print("insn.operands[1].type == X86_OP_REG")
						#print(insn.reg_name(insn.operands[1].value.reg))
						#print(str(info.state.registers.load(insn.reg_name(insn.operands[1].value.reg))))
						#print(str(info.state.registers.load("rax")))

						#print(hex(info.state.addr))
						reg_name = insn.reg_name(insn.operands[0].value.reg)
						if reg_name.endswith("l"):
							reg_name = "r" + reg_name[0] + "x"
						elif reg_name.endswith("x") and len(reg_name) == 2:
							reg_name = "r" + reg_name
						elif reg_name.startswith("e"):
							reg_name = "r" + reg_name[1:]

						#print(reg_name)

						if "atomic_rax" in str(info.state.registers.load(reg_name)):
							used_in_testcmp = True
							defined_once_root_func_addresses.add(get_enclosing_func_addr_1(info.state.addr))

					break


			if info.state.addr == resolve_end:
				#print("exe finish at: " + hex(info.state.addr))
				#print(info.state.registers.load("rax"))
				break

			#print(hex(info.state.addr))
			#print(info.state.registers.load("rax"))

			info.succs = []

			info.succs = info.project.factory.successors(info.state, num_inst=1).successors
				
			info.states.extend(info.succs)


	defined_once_funcs = set()
	for defined_once_root_func_address in sorted(defined_once_root_func_addresses):
		#print("*")
		#print(hex(defined_once_root_func_address))
		#print(get_enclosing_func_name_1(defined_once_root_func_address))

		# find recursively callee functions
		caller_addr = defined_once_root_func_address

		work = [caller_addr]
		defined_once_funcs.add(caller_addr)
		visited = set()

		while len(work) != 0:
			addr = work.pop()
			#print(hex(addr))
			if addr in info.callgraph and addr not in visited:
				visited.add(addr)
				for p in info.callgraph[addr]:
					work.append(p[1])
					defined_once_funcs.add(p[1])

	for defined_once_func in sorted(defined_once_funcs):
		#print(hex(func))
		pass


	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				if get_enclosing_func_addr_1(race_sites[0][1]) in defined_once_funcs and get_enclosing_func_addr_1(race_sites[1][1]) in defined_once_funcs:
					#print("*")
					#print(info.coarsegvmap[race_sites[0][0]])
					#print(get_enclosing_func_name_1(race_sites[0][1]))
					#print(get_enclosing_func_name_1(race_sites[1][1]))
					#print(hex(race_sites[2]))
					race_sites[2] = 0
	'''

	# handle cases involving functions with same name in a binary
	# eliminate those races which are actually noises

	duplicatefuncaddrs = set()
	

	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				if get_enclosing_func_addr(race_sites[0][1]) == -0x1:
					real_func_addr = get_enclosing_func_addr_1(race_sites[0][1])
					real_func_name = info.func_addr_map[real_func_addr][0]
					maped_func_name = real_func_name
					maped_func_addr = info.func_name_map[maped_func_name][0]
					duplicatefuncaddrs.add(real_func_addr)
					duplicatefuncaddrs.add(maped_func_addr)
				if get_enclosing_func_addr(race_sites[1][1]) == -0x1:
					real_func_addr = get_enclosing_func_addr_1(race_sites[1][1])
					real_func_name = info.func_addr_map[real_func_addr][0]
					maped_func_name = real_func_name
					maped_func_addr = info.func_name_map[maped_func_name][0]
					duplicatefuncaddrs.add(real_func_addr)
					duplicatefuncaddrs.add(maped_func_addr)

	#print("duplicatefuncaddrs:")
	#for duplicatefuncaddr in sorted(duplicatefuncaddrs):
	#	print(hex(duplicatefuncaddr))


	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				if get_enclosing_func_addr(race_sites[0][1]) == -0x1 or get_enclosing_func_addr_1(race_sites[0][1]) in duplicatefuncaddrs:
					race_sites[2] = 0
				if get_enclosing_func_addr(race_sites[1][1]) == -0x1 or get_enclosing_func_addr_1(race_sites[0][1]) in duplicatefuncaddrs:
					race_sites[2] = 0

	# eliminate racing pairs with known once function
	temp_race_sites_map = {}
	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			#print("*")
			#print(hex(race_sites[0][1]))
			#print(hex(race_sites[1][1]))
			func_addr_1 = get_enclosing_func_addr_1(race_sites[0][1])
			func_name_1 = info.func_addr_map[func_addr_1][0]
			func_addr_2 = get_enclosing_func_addr_1(race_sites[1][1])
			func_name_2 = info.func_addr_map[func_addr_2][0]
			#print(func_name_1)
			#print(func_name_2)
			if "oe_once" in func_name_1 or "oe_pthread_once" in func_name_1 or "pthread_once" in func_name_1 or ("Once" in func_name_1 and "call_once" in func_name_1):
				pass
			elif "oe_once" in func_name_2 or "oe_pthread_once" in func_name_2 or "pthread_once" in func_name_2 or ("Once" in func_name_2 and "call_once" in func_name_2):
				pass
			else:
				temp_race_sites_map[gv_addr] = copy.deepcopy(info.race_sites_map[gv_addr])
	info.race_sites_map = copy.deepcopy(temp_race_sites_map)



	
	# output exploitable analysis results

	# concise output
	'''
	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				print("*")
				print("access1:")
				print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))
				print("access2:")
				print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))
				print("exploitable_type:")
				print(hex(race_sites[2]))

	if info.args.output:
		info.outputfile = open(os.path.realpath(info.args.output), "w") 
		for gv_addr in sorted(info.race_sites_map):
			for race_sites in info.race_sites_map[gv_addr]:
				if race_sites[2] != 0:
					info.outputfile.write("*\n")
					info.outputfile.write("access1:\n")
					info.outputfile.write(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]) + "\n")
					info.outputfile.write("access2:\n")
					info.outputfile.write(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]) + "\n")
					info.outputfile.write("exploitable_type:\n")
					info.outputfile.write(hex(race_sites[2]) + "\n")
		info.outputfile.close()
	'''

	# detailed output
	'''
	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				print("*")
				print("global variable:")
				if race_sites[0][1] not in info.insnlinesmap:
					print("-0x1")
				else:
					line = info.insnlinesmap[race_sites[0][1]]
					if "<" in line and ">" in line:
						print(line[line.index("<") + 1: line.index(">")])
					else:
						print("-0x1")

				print("access1:")

				print("function1:")
				if get_enclosing_func_addr(race_sites[0][1]) == -0x1:
					print("-0x1")
				else:
					print(info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0])

				print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))

				print("access2:")

				print("function2:")
				if get_enclosing_func_addr(race_sites[1][1]) == -0x1:
					print("-0x1")
				else:
					print(info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0])

				print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

				print("exploitable_type:")
				print(hex(race_sites[2]))
	'''

	if info.args.output:
		info.outputfile = open(os.path.realpath(info.args.output), "w") 
		for gv_addr in sorted(info.race_sites_map):
			for race_sites in info.race_sites_map[gv_addr]:
				if race_sites[2] != 0:

					info.outputfile.write("*\n")

					info.outputfile.write("global variable:\n")
					if race_sites[0][1] not in info.insnlinesmap:
						info.outputfile.write("-0x1\n")
					else:
						line = info.insnlinesmap[race_sites[0][1]]
						if "<" in line and ">" in line:
							info.outputfile.write(line[line.index("<") + 1: line.index(">")] + "\n")
						else:
							info.outputfile.write("-0x1\n")

					info.outputfile.write("access1:\n")

					info.outputfile.write("function1:\n")
					if get_enclosing_func_addr(race_sites[0][1]) == -0x1:
						info.outputfile.write("-0x1\n")
					else:
						info.outputfile.write(info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0] + "\n")

					info.outputfile.write(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]) + "\n")

					info.outputfile.write("access2:\n")

					info.outputfile.write("function2:\n")
					if get_enclosing_func_addr(race_sites[1][1]) == -0x1:
						info.outputfile.write("-0x1\n")
					else:
						info.outputfile.write(info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0] + "\n")

					info.outputfile.write(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]) + "\n")

					info.outputfile.write("exploitable_type:\n")
					info.outputfile.write(hex(race_sites[2]) + "\n")
		info.outputfile.close()


	# var name to access num map
	global_variable_acesses = {}

	# func name to access num map
	func_acesses = {}

	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				#print("*")
				#print("global variable:\n")

				global_variable = ""
				function1 = ""
				function2 = ""

				if race_sites[0][0] in info.coarsegvmap:
					global_variable = info.coarsegvmap[race_sites[0][0]]
				else:
				#	print("*")
				#	print(hex(race_sites[0][0]))
				#	print(hex(race_sites[0][1]))
				#	print(hex(race_sites[0][2]))
				#	print(hex(race_sites[1][0]))
				#	print(hex(race_sites[1][1]))
				#	print(hex(race_sites[1][2]))
					global_variable = hex(race_sites[0][0])

				if global_variable not in global_variable_acesses:
					global_variable_acesses[global_variable] = 1
				else:
					global_variable_acesses[global_variable] = global_variable_acesses[global_variable] + 1


				#print("access1:")
				#print("function1:")
				if get_enclosing_func_addr(race_sites[0][1]) != -0x1:
					#function1 = info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0] + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[0][1]))
					function1 = info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0]
				elif get_enclosing_func_name_1(race_sites[0][1]) != -0x1:
					#function1 = get_enclosing_func_name_1(race_sites[0][1]) + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[0][1]))
					function1 = get_enclosing_func_name_1(race_sites[0][1])
				else:
					function1 = hex(race_sites[0][1])

				if function1 not in func_acesses:
					func_acesses[function1] = 1
				else:
					func_acesses[function1] = func_acesses[function1] + 1


				#print("access2:")
				#print("function2:")
				if get_enclosing_func_addr(race_sites[1][1]) != -0x1:
					#function2 = info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0] + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[1][1]))
					function2 = info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0]
				elif get_enclosing_func_name_1(race_sites[1][1]) != -0x1:
					#function2 = get_enclosing_func_name_1(race_sites[1][1]) + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[1][1]))
					function2 = get_enclosing_func_name_1(race_sites[1][1])
				else:
					function2 = hex(race_sites[1][1])

				if function2 not in func_acesses:
					func_acesses[function2] = 1
				else:
					func_acesses[function2] = func_acesses[function2] + 1

	# output racing variable accesses
	#for global_variable_access in global_variable_acesses:
	#	print("*")
	#	print(global_variable_access)
	#	print(str(global_variable_acesses[global_variable_access]))

	# output racing function accesses
	#for func_acess in func_acesses:
	#	print("*")
	#	print(func_acess)
	#	print(str(func_acesses[func_acess]))


	# func name to access num map
	func_acesses = {}

	# unique shared var*func1*func2 pairs
	pairs_set = set()

	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				#print("*")
				#print("global variable:\n")

				global_variable = ""
				function1 = ""
				function2 = ""

				if race_sites[0][0] in info.coarsegvmap:
					global_variable = info.coarsegvmap[race_sites[0][0]]
				else:
				#	print("*")
				#	print(hex(race_sites[0][0]))
				#	print(hex(race_sites[0][1]))
				#	print(hex(race_sites[0][2]))
				#	print(hex(race_sites[1][0]))
				#	print(hex(race_sites[1][1]))
				#	print(hex(race_sites[1][2]))
					global_variable = hex(race_sites[0][0])

				if global_variable not in global_variable_acesses:
					global_variable_acesses[global_variable] = 1
				else:
					global_variable_acesses[global_variable] = global_variable_acesses[global_variable] + 1


				#print("access1:")
				#print("function1:")
				if get_enclosing_func_addr(race_sites[0][1]) != -0x1:
					#function1 = info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0] + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[0][1]))
					function1 = info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0]
				elif get_enclosing_func_name_1(race_sites[0][1]) != -0x1:
					#function1 = get_enclosing_func_name_1(race_sites[0][1]) + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[0][1]))
					function1 = get_enclosing_func_name_1(race_sites[0][1])
				else:
					function1 = hex(race_sites[0][1])

				if function1 not in func_acesses:
					func_acesses[function1] = 1
				else:
					func_acesses[function1] = func_acesses[function1] + 1


				#print("access2:")
				#print("function2:")
				if get_enclosing_func_addr(race_sites[1][1]) != -0x1:
					#function2 = info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0] + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[1][1]))
					function2 = info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0]
				elif get_enclosing_func_name_1(race_sites[1][1]) != -0x1:
					#function2 = get_enclosing_func_name_1(race_sites[1][1]) + "_FUNCADDR_" + hex(get_enclosing_func_addr_1(race_sites[1][1]))
					function2 = get_enclosing_func_name_1(race_sites[1][1])
				else:
					function2 = hex(race_sites[1][1])

				if function2 not in func_acesses:
					func_acesses[function2] = 1
				else:
					func_acesses[function2] = func_acesses[function2] + 1

				p = global_variable + "*" + function1 + "*" + function2
				if p not in pairs_set:
					pairs_set.add(p)


	#print("+++++++++")
	#for p in sorted(pairs_set):		 
	#	print(p)


	# output concise racing pairs as a complementary output
	if info.args.output1:
		info.outputfile1 = open(os.path.realpath(info.args.output1), "w")
		for p in sorted(pairs_set):		 
			info.outputfile1.write(p + "\n")
		info.outputfile1.close()






	# gather statistics

	# try assign an id to exploitable races
	id_index = 1
	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				race_sites.append(id_index)
				id_index = id_index + 1
			else:
				race_sites.append(-0x1)

	'''
	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				print("*")
				print("global variable:")
				if race_sites[0][1] not in info.insnlinesmap:
					print("-0x1")
				else:
					line = info.insnlinesmap[race_sites[0][1]]
					if "<" in line and ">" in line:
						print(line[line.index("<") + 1: line.index(">")])
					else:
						print("-0x1")

				print("access1:")

				print("function1:")
				if get_enclosing_func_addr(race_sites[0][1]) == -0x1:
					print("-0x1")
				else:
					print(info.func_addr_map[get_enclosing_func_addr(race_sites[0][1])][0])

				print(hex(race_sites[0][0]) + " " + hex(race_sites[0][1]) + " " + hex(race_sites[0][2]))

				print("access2:")

				print("function2:")
				if get_enclosing_func_addr(race_sites[1][1]) == -0x1:
					print("-0x1")
				else:
					print(info.func_addr_map[get_enclosing_func_addr(race_sites[1][1])][0])

				print(hex(race_sites[1][0]) + " " + hex(race_sites[1][1]) + " " + hex(race_sites[1][2]))

				print("exploitable_type:")
				print(hex(race_sites[2]))

				print("id:")
				print(str(race_sites[3]))
	'''

	'''
	# useless code here
	# find recursively callee functions
	caller_addr = 0x43d550
	#caller_addr = 0x42e770
	#for addr in sorted(info.callgraph):
	#	print("*")
	#	print(hex(addr))
	#	for p in info.callgraph[addr]:
	#		print(hex(p[0]))
	#		print(hex(p[1]))

	#print(get_enclosing_func_name_1(caller_addr))

	work = [caller_addr]
	funcs = set()
	funcs.add(caller_addr)
	visited = set()

	while len(work) != 0:
		addr = work.pop()
		#print(hex(addr))
		if addr in info.callgraph and addr not in visited:
			visited.add(addr)
			for p in info.callgraph[addr]:
				work.append(p[1])
				funcs.add(p[1])
	for func in sorted(funcs):
		#print(hex(func))
		pass


	for gv_addr in sorted(info.race_sites_map):
		for race_sites in info.race_sites_map[gv_addr]:
			if race_sites[2] != 0:
				if get_enclosing_func_addr_1(race_sites[0][1]) in funcs and get_enclosing_func_addr_1(race_sites[1][1]) in funcs:
					#print(info.coarsegvmap[race_sites[0][0]])
					#print(get_enclosing_func_name_1(race_sites[0][1]))
					#print(get_enclosing_func_name_1(race_sites[1][1]))
					#print(str(race_sites[3]))
					#print(hex(race_sites[2]))
					pass
	'''

	# gather statistics for lockset size

	max_lockset_size = 0
	min_lockset_size = 0
	average_lockset_size = 0
	insn_num = len(info.insnaddrs)
	lockset_size_sum = 0
	for insnaddr in info.insnaddrs:
		lockset_size = 0
		if insnaddr in info.lockset:
			lockset_size = len(info.lockset[insnaddr])
		lockset_size_sum = lockset_size_sum + lockset_size
		if lockset_size > max_lockset_size:
			max_lockset_size = lockset_size
		if lockset_size < min_lockset_size:
			min_lockset_size = lockset_size

	average_lockset_size = lockset_size_sum / insn_num

	print("max_lockset_size: " + str(max_lockset_size))
	print("min_lockset_size: " + str(min_lockset_size))
	print("average_lockset_size: " + str(average_lockset_size))

	# gather statistics for history size
	max_history_size = 0
	min_history_size = 0
	average_history_size = 0
	history_num = 0
	history_size_sum = 0

	unique_locks = set()
	for insnaddr in info.insnaddrs:
		if insnaddr in info.lockset:
			for l in sorted(info.lockset[insnaddr]):
				if l != -0x1:
					unique_locks.add(l)
	#print(len(unique_locks))
	history_num = len(info.insnaddrs) * len(unique_locks)

	for insnaddr in info.insnaddrs:
		history_size = 0
		if insnaddr in info.lockhistory:
			for lock_addr in sorted(info.lockhistory[insnaddr]):
				history_size = len(info.lockhistory[insnaddr][lock_addr])
				if history_size > max_history_size:
					max_history_size = history_size
				if history_size < min_history_size:
					min_history_size = history_size
				history_size_sum = history_size_sum + history_size
		else:
			if history_size < min_history_size:
				min_history_size = history_size
	average_history_size = 0
	if history_num != 0:
		average_history_size = history_size_sum / history_num

	print("max_history_size: " + str(max_history_size))
	print("min_history_size: " + str(min_history_size))
	print("average_history_size: " + str(average_history_size))


	# gv_addr to [[insn_addr, access_type]]
	#self.gv_reverse_map = {}

	# gather statistics for shared variables

	sv_r_count = 0
	sv_w_count = 0
	sv_rw_count = 0
	sv_count = 0


	for gv_addr in sorted(info.gv_reverse_map):
		for l in info.gv_reverse_map[gv_addr]:
			sv_count = sv_count + 1
			if l[1] == 1:
				sv_r_count = sv_r_count + 1
			elif l[1] == 2:
				sv_w_count = sv_w_count + 1
			elif l[1] == 3:
				sv_rw_count = sv_rw_count + 1

	print("sv_r_count: " + str(sv_r_count))
	print("sv_w_count: " + str(sv_w_count))
	print("sv_rw_count: " + str(sv_rw_count))
	#print(str(sv_count))
	print("len(info.gv_reverse_map): " + str(len(info.gv_reverse_map)))

	# gather statistics for lock variables and synchronization primitives
	sgx_thread_mutex_lock_func_addresses = []
	sgx_thread_mutex_unlock_func_addresses = []
	sgx_spin_lock_func_addresses = []
	sgx_spin_unlock_func_addresses = []
	sgx_rwlock_func_addresses = []
	sgx_barrier_func_addresses = []
	sgx_reentrant_mutex_lock_func_addresses = []
	sgx_condvar_func_addresses = []
	sgx_once_func_addresses = []


	for mutex_lock_function in info.mutex_lock_functions:
		if mutex_lock_function in info.func_name_map:
			sgx_thread_mutex_lock_func_addresses.append(info.func_name_map[mutex_lock_function][0])

	for mutex_unlock_function in info.mutex_unlock_functions:
		if mutex_unlock_function in info.func_name_map:
			sgx_thread_mutex_unlock_func_addresses.append(info.func_name_map[mutex_unlock_function][0])

	for spin_lock_function in info.spin_lock_functions:
		if spin_lock_function in info.func_name_map:
			sgx_spin_lock_func_addresses.append(info.func_name_map[spin_lock_function][0])

	for spin_unlock_function in info.spin_unlock_functions:
		if spin_unlock_function in info.func_name_map:
			sgx_spin_unlock_func_addresses.append(info.func_name_map[spin_unlock_function][0])

	# handle other specific lock and unlock functions
	for func_name in info.func_name_map:
		if "Spinlock" in func_name and "lock" in func_name:
			info.hasspin = 1
			sgx_spin_lock_func_addresses.append(info.func_name_map[func_name][0])
		if "Spinlock" in func_name and "unlock" in func_name:
			sgx_spin_unlock_func_addresses.append(info.func_name_map[func_name][0])

		if ("Mutex" in func_name and "lock" in func_name and "trylock" not in func_name and "unlock" not in func_name) or (func_name == "__lock"):
			info.hasmutex = 1
			sgx_thread_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex lock")
			#print(hex(info.func_name_map[func_name][0]))

		if ("Mutex" in func_name and "unlock" in func_name) or (func_name == "__unlock"):
			sgx_thread_mutex_unlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex unlock")
			#print(hex(info.func_name_map[func_name][0]))

		# rwlock
		if "RwLock" in func_name and ("read" in func_name or "write" in func_name) and "try_read" not in func_name and "try_write" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "RwLock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock unlock")
			#print(hex(info.func_name_map[func_name][0]))

		if "oe_pthread_rwlock" in func_name and ("rdlock" in func_name or "wrlock" in func_name):
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "oe_pthread_rwlock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

		if "RWLock" in func_name and ("read" in func_name or "write" in func_name) and "try_read" not in func_name and "try_write" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "RWLock" in func_name and "unlock" in func_name:
			sgx_rwlock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Rwlock unlock")
			#print(hex(info.func_name_map[func_name][0]))

		# barrier
		if "Barrier" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_barrier_func_addresses.append(info.func_name_map[func_name][0])


		# reentrant mutex
		if "Reentrant" in func_name and "lock" in func_name and "trylock" not in func_name and "unlock" not in func_name:
			info.hasmutex = 1
			sgx_reentrant_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex lock")
			#print(hex(info.func_name_map[func_name][0]))

		if "Reentrant" in func_name and "unlock" in func_name:
			sgx_reentrant_mutex_lock_func_addresses.append(info.func_name_map[func_name][0])

			#print("*")
			#print("Mutex unlock")
			#print(hex(info.func_name_map[func_name][0]))


		# condition variable
		if "Condvar" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "Condvar" in func_name and ("signal" in func_name or "broadcast" in func_name or "notify" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "sgx_thread_cond" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "sgx_thread_cond" in func_name and ("signal" in func_name or "broadcast" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "oe_pthread_cond" in func_name and "wait" in func_name:
			info.hasmutex = 1
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])

		if "oe_pthread_cond" in func_name and ("signal" in func_name or "broadcast" in func_name):
			sgx_condvar_func_addresses.append(info.func_name_map[func_name][0])


		# once variable
		if "oe_once" in func_name or "oe_pthread_once" in func_name or "pthread_once" in func_name or ("Once" in func_name and "call_once" in func_name):
			sgx_once_func_addresses.append(info.func_name_map[func_name][0])



	# once var
	oncesiteaddresses = []
	for addr in sorted(info.callinsnmap):
		if info.callinsnmap[addr] in sgx_once_func_addresses:
			oncesiteaddresses.append(addr)




	mutex_count = 0
	spin_count = 0
	once_count = len(oncesiteaddresses)

	# a local dict from lock site addr to [type, transfer_type]
	locksitetypemap = {}

	# get call site of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock
	for addr in sorted(info.callinsnmap):
		if info.callinsnmap[addr] in sgx_thread_mutex_lock_func_addresses:
			locksitetypemap[addr] = [0, 0]
			mutex_count = mutex_count + 1
		elif info.callinsnmap[addr] in sgx_thread_mutex_unlock_func_addresses:
			mutex_count = mutex_count + 1
			locksitetypemap[addr] = [1, 0]
		elif info.callinsnmap[addr] in sgx_spin_lock_func_addresses:
			spin_count = spin_count + 1
			locksitetypemap[addr] = [2, 0]
		elif info.callinsnmap[addr] in sgx_spin_unlock_func_addresses:
			spin_count = spin_count + 1
			locksitetypemap[addr] = [3, 0]

	# get jmp site of sgx_thread_mutex_lock, sgx_thread_mutex_unlock, sgx_spin_lock, sgx_spin_unlock
	for addr in sorted(info.jmpinsnmap):
		if info.jmpinsnmap[addr][0] in sgx_thread_mutex_lock_func_addresses:
			mutex_count = mutex_count + 1
			locksitetypemap[addr] = [0, 1]
		elif info.jmpinsnmap[addr][0] in sgx_thread_mutex_unlock_func_addresses:
			mutex_count = mutex_count + 1
			locksitetypemap[addr] = [1, 1]
		elif info.jmpinsnmap[addr][0] in sgx_spin_lock_func_addresses:
			spin_count = spin_count + 1
			locksitetypemap[addr] = [2, 1]
		elif info.jmpinsnmap[addr][0] in sgx_spin_unlock_func_addresses:
			spin_count = spin_count + 1
			locksitetypemap[addr] = [3, 1]



	print("mutex_count: " + str(mutex_count))
	print("spin_count: " + str(spin_count))
	print("once_count: " + str(once_count))
	print("unique_locks: " + str(len(unique_locks)))



def data_race_detection():
	lockset_analysis()
	exploitable_analysis()


def variable_analysis():
	global_variable_analysis()
	lock_variable_analysis()


def parse_parameters():
	# parameter handling
	'''
	print("parameters:")
	for arg in sys.argv[1:]:
		print(arg)
	if len(sys.argv) != 2:
		print("ERROR: accept exactly 1 parameters.")
		print("param1: binary to load. Shared library .so file or executable.")
		exit(-1)
	'''
	parser = argparse.ArgumentParser(description='SGXRace: Detecting exploitable data races in enclave code.')
	parser.add_argument("-input", help = "input enclave binary file", required=True)
	parser.add_argument("-output", help = "output data race result file", required=False)
	parser.add_argument("-output1", help = "complementary output data race result file", required=False)
	parser.add_argument("-output2", help = "debug output file", required=False)
	parser.add_argument("-app", help = "detect data races in application code only", action="store_true", required=False)
	parser.add_argument("-fast", help = "detect data races fast", action="store_true", required=False)
	info.args = parser.parse_args()
	#print(info.args.input)
	#print(info.args.output)
	#print(info.args.output1)
	#print(info.args.app)
	#print(info.args.fast)


def main():

	# check parameters
	parse_parameters()

	# load binary
	load_binary()

	# preprocessing
	preprocessing()

	#print(get_variable_section(0x648190))
	#print(hex(v_dyn_addr_to_binary_offset(0x648b50)))
	#print(hex(read_variable_initial_value_in_binary(0x648b50, 16)))

	info.start1 = time.time()

	# variable analysis
	variable_analysis()

	info.end1 = time.time()

	info.start2 = time.time()

	# data race detection algorithm
	data_race_detection()

	info.end2 = time.time()

	print("phase 1 time:")
	print(str(info.end1 - info.start1))

	print("phase 2 time:")
	print(str(info.end2 - info.start2))

#
#main function
#
if __name__ == "__main__":
	main()
