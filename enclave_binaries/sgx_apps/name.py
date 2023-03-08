#!/usr/bin/python3
import os
import copy
import subprocess



names = ["mbedtls-SGX", "intel-sgx-ssl", "sgx-reencrypt", "TaLoS", "sgx-aes-gcm", "CryptoEnclave", "SGXCryptoFile", "SGX-AES-256", "SGX-reencryption", "seal_SGX", "raft-sgx", "sgx-sign-data", "sgx-pkcs11", "flowcontrol", "LibSEAL", "SGX-DPDK", "sk-sgx", "ovs-sgx", "SGXEnabledAccess", "sgx-ipc", "OVS_SGX", "SGX-server-client", "SGX-p2p", "MPI-SGX-Demo", "wave-sgx-demo", "TPM-Remote-Attestation-using-Intel-SGX", "SGXRemoteAttestation", "SGXLAB", "SGX-Attestation", "SGX_Attestation_RSA", "intelSGX-ParallelLocalAttestation", "sgx-genome-variants-search", "sgx-gwas", "BiORAM-SGX", "bioinfo-meets-sgx", "OTP-SGX-Server", "SGX-Password-Manager", "passwd-mgr-with-intel-sgx", "sgx-password-manager", "password-manager", "secpass", "Password-Manager-MPI-Demo", "crust-client", "webassemblyEnclave", "lua-sgx", "go-sgx", "cave", "bitcoin-sgx", "Proof-Of-Luck-Cryptocurrency", "SGX_SQLite", "stealthdb", "mnist-sgx", "sgx-db", "SGX-protected-fs-demo", "sgx_protect_file", "sgx-fs", "intel-sgx-deep-learning", "sgx_protect_file", "sgx-fs", "sgx-gmp-demo", "eigen-sgx", "sgx-mpi", "hot-calls", "zlib-sgx", "SGXImgProcessFile", "SGXORAM", "OS-Project", "sip-sgx", "sgx_scheduling", "gbc_sgx", "MEE_Overhead_SGX", "SGX_secure_function_evaluation", "SGX-OS-Launcher"]



'''
for name in names:
	for root, dirs, files in os.walk("."):
		for d in dirs:
			if name in d:
				#print(name)
				print(d)
'''



dirs = ["001_mbedtls-SGX", "002_intel-sgx-ssl", "004_sgx-reencrypt", "008_TaLoS", "015_sgx-aes-gcm", "020_CryptoEnclave", "047_SGXCryptoFile", "059_SGX-AES-256", "085_SGX-reencryption", "091_seal_SGX", "108_raft-sgx", "150_sgx-sign-data", "159_sgx-pkcs11", "185_flowcontrol", "026_LibSEAL", "040_SGX-DPDK", "063_sk-sgx", "070_ovs-sgx", "079_SGXEnabledAccess", "113_sgx-ipc", "114_OVS_SGX", "143_SGX-server-client", "154_SGX-p2p", "158_MPI-SGX-Demo", "168_wave-sgx-demo", "035_TPM-Remote-Attestation-using-Intel-SGX", "043_SGXRemoteAttestation", "084_SGXLAB", "121_SGX-Attestation", "165_SGX_Attestation_RSA", "174_intelSGX-ParallelLocalAttestation", "053_sgx-genome-variants-search", "055_sgx-gwas", "078_BiORAM-SGX", "132_bioinfo-meets-sgx", "139_OTP-SGX-Server", "156_SGX-Password-Manager", "157_passwd-mgr-with-intel-sgx", "164_sgx-password-manager", "186_password-manager", "188_secpass", "195_Password-Manager-MPI-Demo", "067_crust-client", "069_webassemblyEnclave", "093_lua-sgx", "101_go-sgx", "190_cave", "099_bitcoin-sgx", "194_Proof-Of-Luck-Cryptocurrency", "016_SGX_SQLite", "028_stealthdb", "097_mnist-sgx", "112_sgx-db", "021_SGX-protected-fs-demo", "057_sgx_protect_file", "072_sgx-fs", "087_intel-sgx-deep-learning", "057_sgx_protect_file", "072_sgx-fs", "042_sgx-gmp-demo", "100_eigen-sgx", "110_sgx-mpi", "065_hot-calls", "073_zlib-sgx", "081_SGXImgProcessFile", "083_SGXORAM", "086_OS-Project", "111_sip-sgx", "123_sgx_scheduling", "129_gbc_sgx", "147_MEE_Overhead_SGX", "160_SGX_secure_function_evaluation", "163_SGX-OS-Launcher"]


'''
mmax = 0
mmin = 9999999999999999

for d in dirs:
	binary = "./" + d + "/enclave.signed.so"
	proc = subprocess.Popen(['ls', "-lh", binary], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	tmp = proc.stdout.read().decode("utf-8").strip().split()[4]
	tmp1 = float(tmp[:len(tmp)-1])
	if "K" in tmp:
		tmp1 = tmp1 * 1024
	if "M" in tmp:
		tmp1 = tmp1 * 1024 * 1024

	#print(tmp)
	#print(tmp1)
	if tmp1 > mmax:
		mmax = tmp1
	if tmp1 < mmin:
		mmin = tmp1

	#tmp1 = tmp1/1000000
	tmp1 = tmp1/25000000
	tmp2 = str(tmp1)
	tmp2 = tmp2[:tmp2.index(".")+3]
	print(tmp2)



#print(mmax)
#print(mmin)
#print(mmax/mmin)
'''

'''
for d in dirs:
	gv_file = "./" + d + "/enclave.signed.so_gv_reverse_map_tmp_file"
	proc = subprocess.Popen(['grep', "-c", "0x3", gv_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
	tmp = proc.stdout.read().decode("utf-8").strip()
	print(tmp)
'''

for d in dirs:
	locksetfile = "./" + d + "/enclave.signed.so_lockset_tmp_file"

	lockset = {}

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

	'''
	total = 0
	for addr in sorted(lockset):
		total = total + len(lockset[addr])
	#if len(lockset) == 0:
		#print(0)
	#else:
		#ave = float(total) / float(len(lockset))
		#print(ave)

	asmfile = "./" + d + "/enclave.signed.so_asm"
	f = open(asmfile, "r")
	lines = f.readlines()

	print(float(total) / float(len(lines)))

	f.close()
	'''



	# get all unique locks
	all_locks = set()
	for addr in sorted(lockset):
		#print("*")
		#print(hex(addr))
		#print("[", end='')
		for l in lockset[addr]:
			#print(hex(l) + " ", end='')
			if l != -0x1:
				all_locks.add(l)
		#print("]")

	#for l in sorted(all_locks):
	#	print(hex(l))

	lockhistory = {}

	for addr in sorted(lockset):
		lockhistory[addr] = {}
		locks = set()
		if -0x1 in lockset[addr]:
			locks = copy.deepcopy(all_locks)
		else:
			locks = copy.deepcopy(lockset[addr])

		for lock in sorted(locks):
			tmpset = copy.deepcopy(locks)
			tmpset.remove(lock)
			lockhistory[addr][lock] = tmpset

	totalhis = 0
	cou = 0

	for addr in sorted(lockhistory):
		for lock in lockhistory[addr]:
			totalhis = totalhis + len(lockhistory[addr][lock])
		cou = cou + 1


	asmfile = "./" + d + "/enclave.signed.so_asm"
	f = open(asmfile, "r")
	lines = f.readlines()

	if len(all_locks) == 0:
		print(0)
	else:
		print(float(totalhis) / float(len(lines)))
		#print(float(totalhis) / float(cou))

	f.close()


	#	print("*")
	#	print(hex(addr))
	#	for lock_addr in sorted(lockhistory[addr]):
	#		print("lock history for lock " + hex(lock_addr) + ":")
	#		print("[", end='')
	#		for l in lockhistory[addr][lock_addr]:
	#			print(hex(l) + " ", end='')
	#		print("]")














	'''
	uset = set()
	for addr in sorted(lockset):
		uset = uset.union(lockset[addr])
	#	print("*")
	#	print(hex(addr))
	#	print("[", end='')
	#	for l in lockset[addr]:
	#		print(hex(l) + " ", end='')
	#	print("]")

	print(len(uset))


	asmfile = "./" + d + "/enclave.signed.so_asm"
	
	f = open(asmfile, "r")
	lines = f.readlines()

	acc = 0

	for line in lines:
		if "call" in line and "mutex_lock>" in line:
			acc = acc + 1
		if "call" in line and "mutex_unlock>" in line:
			acc = acc + 1
		if "call" in line and "spin_lock>" in line:
			acc = acc + 1
		if "call" in line and "spin_unlock>" in line:
			acc = acc + 1
		if "jmp" in line and "mutex_lock>" in line:
			acc = acc + 1
		if "jmp" in line and "mutex_unlock>" in line:
			acc = acc + 1
		if "jmp" in line and "spin_lock>" in line:
			acc = acc + 1
		if "jmp" in line and "spin_unlock>" in line:
			acc = acc + 1

	print(acc)

	'''










