#!/usr/bin/python3
import os
import copy
import subprocess




'''
unique_gv = 0

for root, dirs, files in os.walk("."):
	#for name in dirs:
	#	print(os.path.join(root, name))
	for name in files:
		#print(os.path.join(root, name))
		if "gv_reverse_map_tmp_file" in name:
			gv_reverse_mapfile = os.path.join(root, name)
			#print(gv_reverse_mapfile)

			gv_reverse_map = {}

			f = open(gv_reverse_mapfile, "r")
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
						gv_reverse_map[gv_addr] = copy.deepcopy(accesses)
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
						gv_reverse_map[gv_addr] = copy.deepcopy(accesses)
						gv_addr = 0
						accesses = []
						index = 0

				line_num = line_num + 1

			f.close()

			#print(len(gv_reverse_map))
			#unique_gv = unique_gv + len(gv_reverse_map)


			count = 0
			for gv_addr in sorted(gv_reverse_map):
				count = 0
				for l in gv_reverse_map[gv_addr]:
					if l[1] == 0x1:
						count = count + 1
				unique_gv = unique_gv + count


#print(unique_gv)
#print(float(unique_gv)/float(73))
'''

unique_lock = 0


for root, dirs, files in os.walk("."):
	#for name in dirs:
	#	print(os.path.join(root, name))
	for name in files:
		#print(os.path.join(root, name))
		if "lockset_tmp_file" in name:
			locksetfile = os.path.join(root, name)
			print(locksetfile)

			lockset = {}
			uset = set()

			f = open(locksetfile, "r")
			lines = f.readlines()

			addr = 0
			locks = set()
			index = 0
			line_num = 0

			for line in lines:
				if "*" in line:
					if addr != 0:
						lockset[addr] = copy.deepcopy(locks)
						uset = uset.union(lockset[addr])
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
						lockset[addr] = copy.deepcopy(locks)
						addr = 0
						locks = set()
						index = 0

				line_num = line_num + 1

			f.close()

			#print(len(uset))

			#unique_lock = unique_lock + len(uset)

			dfilename = os.path.abspath(locksetfile[:locksetfile.index(".so")+3] + "_asm")
			#print(dfilename)

			uset = []
			last = 0

			'''
			for addr in sorted(lockset):
				if addr > last + 0x20 or addr < last - 0x20:
					for l in lockset[addr]:
						if l > 0x400000:
							s = "# " + hex(l - 0x400000)[2:]
							#print(s)
							proc = subprocess.Popen(['grep', "-B", "300", "-A", "300", s, dfilename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
							tmp = proc.stdout.read().decode("utf-8") 
							#print(tmp.__class__)
							if "mutex" in tmp:
							#if "spin" in tmp:
							#if not "mutex" in tmp and not "spin" in tmp:
								uset.append(l)
				last = addr
			unique_lock = unique_lock + len(uset)
			'''

			linescount = 0
			proc = subprocess.Popen(['wc', "-l", dfilename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
			tmp = proc.stdout.read().decode("utf-8").strip().split()[0]
			#print(tmp)


			sizesum = 0
			subaverage = 0
			m = 0

			for addr in sorted(lockset):
				sizesum = sizesum + len(lockset[addr])
				if len(lockset[addr]) > m:
					m = len(lockset[addr])


			if len(lockset) != 0:
				#subaverage = float(sizesum) / float(len(lockset))
				subaverage = float(sizesum) / (float(tmp))# - float(len(lockset)))


			unique_lock = unique_lock + subaverage


#print(float(unique_lock) / float(73))
#print(m)























