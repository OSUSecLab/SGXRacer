import sys

def main():
	#print(sys.argv[1])
	f = open(sys.argv[1])
	lines = f.readlines()
	count = 0
	v_set = set()
	f_set = set()
	for line in lines:
		#print(line)
		line = line.strip()
		count = count + 1
		v = line[:line.index("*")]
		#if not v in v_set:
		#	print(v)
		#print(v)
		v_set.add(v)
		s = line.split("*")
		#print(line)
		#print(s)
		if not s[1] in f_set:
			print(s[1])
		f_set.add(s[1])
		if not s[2] in f_set:
			print(s[2])
		f_set.add(s[2])
		
	#print("v_set size:" + str(len(v_set)))
	#print("total detected races: " + str(count))
	

#
#main function
#
if __name__ == "__main__":
	main()
