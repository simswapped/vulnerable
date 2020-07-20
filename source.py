# <3 - shark

import argparse
import os
from datetime import datetime
import indicators
from indicator_config import *
import sys
import time
import hashlib
from pyfiglet import Figlet

parser = argparse.ArgumentParser(description= "TROMMEL: Sift Through Directories of Files to Identify Indicators That May Contain Vulnerabilities")
parser.add_argument("-p","--path", required=True, help="Directory to Search")
parser.add_argument("-o","--output", required=True, default='Unspecified_Name', help="Output TROMMEL Results File Name (no spaces)")
parser.add_argument("-d","--dir", required=True, help="Directory to Write Output TROMMEL Results")

args = vars(parser.parse_args())

path = args['path']
output = args['output']
dir_output = args['dir']

def main():

	yrmoday = datetime.now().strftime("%Y%m%d_%H%M%S")

	trommel_output = open(dir_output + output+'_TROMMEL_'+yrmoday, 'w')

	trommel_hash_ouput = open(dir_output + output + "_TROMMEL_Hash_Results_"+yrmoday, 'w')

	f = Figlet(font='shadow')
	print (f.renderText('\nTROMMEL'))
	trommel_output.write(f.renderText('TROMMEL'))
	trommel_hash_ouput.write(f.renderText('TROMMEL'))

	print ("\nTROMMEL is working to sift through the directory of files.\n\nResults will be saved to '%s_TROMMEL_%s'.\n" % (output, yrmoday))
	print ("TROMMEL file hashes will be saved to '%s_TROMMEL_Hash_Results_%s'\n" % (output, yrmoday))

	trommel_output.write("TROMMEL Results File Name: %s\nDirectory: %s\n" % (output,path))

	total = 0
	for root, dirs, files in os.walk(path, followlinks=False):
		total += len(files)
	trommel_output.write("There are %d total files within the directory.\n\n" % total)
	trommel_hash_ouput.write("There are %d total files within the directory.\n\n" % total)

	trommel_output.write("Results could be vulnerabilities. These results should be verified as false positives may exist.\n\n")

	for root, dirs, files in os.walk(path):

		for names in files:
			ff = os.path.join(root,names)

			if busybox_bin in ff:
				value = check_arch(ff, trommel_output)
				if value != None:
					print ("Based on the binary 'busybox' the instruction set architecture is %s.\n" % value)


			if not os.path.islink(ff):

				dev_kw = "/dev/"
				if not dev_kw in ff:

					if path and output:
						indicators.kw(ff, trommel_output, names)

					try:
						with open(ff,"rb") as fhash:
							bytes = fhash.read() 
							md5_hash = hashlib.md5(bytes).hexdigest()
							sha1_hash = hashlib.sha1(bytes).hexdigest()
							sha256_hash = hashlib.sha256(bytes).hexdigest()
							trommel_hash_ouput.write("File name: %s, Hashes: %s, %s, %s\n" % (ff, md5_hash, sha1_hash, sha256_hash))
					except:
						trommel_hash_ouput.write("The following file, %s, was not hashed." % ff)

if __name__ == '__main__':
	main()
