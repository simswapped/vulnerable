# <3 - shark

import magic
import re
import os
import codecs
import collections
from indicator_config import *


def read_search_kw(ff, keyword, trommel_output):
	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(keyword, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword: '%s', File: %s, Offset(s) in File: \n" % (keyword, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
	except IOError:
		pass

def read_search_case_kw(ff, keyword, trommel_output):
	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(keyword, text):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword: '%s', File: %s, Offset(s) in File: \n" % (keyword, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
	except IOError:
		pass

def read_search_lua_kw(ff, keyword, trommel_output):
	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			hits = re.findall(keyword, text)
			if hits:
				trommel_output.write("Lua Script file, Keyword: '%s', File: %s, Keyword Hits in File: %d\n" % (keyword, ff, len(hits)))
	except IOError:
		pass


def kw(ff, trommel_output, names):

	if busybox_bin in ff:
		value = check_arch(ff, trommel_output)
		if value != None:
			trommel_output.write("Based on the binary 'busybox' the instruction set architecture is %s.\n" % value)

	if opt_dir in ff:
		trommel_output.write("The follow file was found in the /opt (i.e. 3rd party software) directory: %s.\n" % ff)

	if ssh_bin in ff:
		trommel_output.write("Non-Plain Text File, ssh binary file: %s\n" % ff)
	if sshd_bin in ff:
		trommel_output.write("Non-Plain Text File, sshd binary file: %s\n" % ff)
	if scp_bin in ff:
		trommel_output.write("Non-Plain Text File, scp binary file: %s\n" % ff)
	if sftp_bin in ff:
		trommel_output.write("Non-Plain Text File, sftp binary file: %s\n" % ff)
	if tftp_bin in ff:
		trommel_output.write("Non-Plain Text File, tftp binary file: %s\n" % ff)
	if dropbear_bin in ff:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			drop_term = 'Dropbear server v[0-9]{4}\.[0-9]{2,3}'
			drop_hit = re.search(drop_term, text)
			if drop_hit:
				trommel_output.write("The Dropbear (late 2011 or newer) binary found is %s [may need to emulate environment]\n" % drop_hit.group())
	if telnet_bin in ff:
		trommel_output.write("Non-Plain Text File, telnet binary file: %s\n" % ff)
	if telnetd_bin in ff:
		trommel_output.write("Non-Plain Text File, telnetd binary file: %s\n" % ff)
	if openssl_bin in ff:
		trommel_output.write("Non-Plain Text File, openssl binary file: %s\n" % ff)
	if busybox_bin in ff:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			bb_term = 'BusyBox v[0-9]{1}\.[0-9]{1,2}\.[0-9]{1}|BusyBox v[0-9]{1}\.[0-9]{1,2}'
			bb_hit = re.search(bb_term, text)
			if bb_hit:
				trommel_output.write("The BusyBox binary found is %s [may need to emulate environment]\n" % bb_hit.group())
	if other_bins in ff:
		trommel_output.write("Non-Plain Text File, .bin file: %s\n" % ff)

	if passwd in ff:
		trommel_output.write("A passwd file: %s\n" % ff)
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			user_term = '.*/bin/sh'
			sh_user_hit = re.finditer(user_term, text)
			for m in sh_user_hit:
				trommel_output.write("Users with shell access, [%s] in this passwd file, %s\n" %(m.group(),ff))
	if shadow in ff:
		trommel_output.write("A shadow file: %s\n" % ff)
	if psk_hits in ff:
		trommel_output.write("A .psk file: %s\n" % ff)
	if key_pass in ff:
		trommel_output.write("A keypass file: %s\n" % ff)
	if k_wallet in ff:
		trommel_output.write("A kwallet file: %s\n" % ff)
	if open_vpn in ff:
		trommel_output.write("An ovpn file: %s\n" % ff)
	if pgp_log in ff:
		trommel_output.write("A pgplog file: %s\n" % ff)
	if pgp_policy in ff:
		trommel_output.write("A pgppolicy.xml file: %s\n" % ff)
	if pgp_prefs in ff:
		trommel_output.write("A pgpprefs.xml file: %s\n" % ff)
	if priv_kw in ff:
		trommel_output.write("A file with private in the file name: %s\n" % ff)
	if secret_kw in ff:
		trommel_output.write("A file with secret in the file name: %s\n" % ff)
	if javaks in ff:
		trommel_output.write("A JavaKeyStore file: %s\n" % ff)
	if sftpconfig in ff:
		trommel_output.write("A sftp-config file: %s\n" % ff)
	if bitcoinfile in ff:
		trommel_output.write("A Bitcoin Wallet: %s\n" % ff)
	if pwd_safe in ff:
		trommel_output.write("A Password Safe file: %s\n" % ff)


	if auth_key_file in ff:
		trommel_output.write("An authorized_keys file: %s\n" % ff)
	if host_key_file in ff:
		trommel_output.write("A host_key file: %s\n" % ff)
	if id_rsa_file in ff:
		trommel_output.write("An id_rsa file: %s\n" % ff)
	if id_dsa_file in ff:
		trommel_output.write("An id_dsa file: %s\n" % ff)
	if dotPub in ff:
		trommel_output.write("A .pub file: %s\n" % ff)
	if id_ecdsa_file in ff:
		trommel_output.write("An id_ecdsa file: %s\n" % ff)
	if id_ed25519_file in ff:
		trommel_output.write("An id_ed25519 file: %s\n" % ff)
	read_search_kw(ff, id_dsa_file, trommel_output)
	read_search_kw(ff, host_key_file, trommel_output)
	read_search_kw(ff, auth_key_file, trommel_output)
	read_search_kw(ff, id_rsa_file, trommel_output)
	read_search_kw(ff, id_ecdsa_file, trommel_output)
	read_search_kw(ff, id_ed25519_file, trommel_output)

	if pem in ff:
		trommel_output.write("A SSL related .pem file: %s\n" % ff)
	if crt in ff:
		trommel_output.write("A SSL related .crt file: %s\n" % ff)
	if cer in ff:
		trommel_output.write("A SSL related .cer file: %s\n" % ff)
	if p7b in ff:
		trommel_output.write("A SSL related .p7b file: %s\n" % ff)
	if p12 in ff:
		trommel_output.write("A SSL related .p12 file: %s\n" % ff)
	if dotKey in ff:
		trommel_output.write("A SSL related .key file: %s\n" % ff)
	if p15 in ff:
		trommel_output.write("A SSL related .p15 file: %s\n" % ff)
	if cgi_file in ff:
		trommel_output.write("A cgi file was found: %s\n" % ff)

	read_search_kw(ff, upgrade_kw, trommel_output)
	read_search_kw(ff, admin_kw, trommel_output)
	read_search_kw(ff, root_kw, trommel_output)
	read_search_kw(ff, password_kw, trommel_output)
	read_search_kw(ff, passwd_kw, trommel_output)
	read_search_kw(ff, pwd_kw, trommel_output)
	read_search_kw(ff, dropbear_kw, trommel_output)
	read_search_kw(ff, ssl_kw, trommel_output)
	read_search_kw(ff, telnet_kw, trommel_output)
	read_search_kw(ff, crypt_kw, trommel_output)
	read_search_kw(ff, auth_kw, trommel_output)
	read_search_kw(ff, sql_kw, trommel_output)
	read_search_kw(ff, passphrase_kw, trommel_output)
	read_search_kw(ff, rsa_key_pair, trommel_output)
	read_search_kw(ff, secretkey_kw, trommel_output)
	read_search_kw(ff, ssh_hot_keys, trommel_output)
	read_search_kw(ff, username_kw, trommel_output)
	read_search_kw(ff, secret_kw, trommel_output)
	read_search_kw(ff, shell_kw, trommel_output)
	read_search_kw(ff, port_kw, trommel_output)
	read_search_kw(ff, debug_kw, trommel_output)

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as privkey_keyword:
			text = privkey_keyword.read()
			hits = re.findall(private_key_kw, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(private_key_kw, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword Variation: 'private key', File: %s, Offset(s) in File: \n" % (ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword Variation: 'private key', File: %s, Keyword Hits in File: %d\n" % (ff, len(hits)))
	except IOError:
		pass

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as ipaddr_keyword:
			text = ipaddr_keyword.read()
			hits = re.findall(ipaddr, text, re.S)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(ipaddr, text, re.S):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword IP Address: '%s', File: %s, Offset(s) in File: \n" % (m.group(0), ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					for h in hits:
						trommel_output.write("Plain Text File, Keyword IP Address: %s, File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as url_keyword:
			text = url_keyword.read()
			hits = re.findall(urls, text, re.S)
			for h in hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(urls, text, re.S):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword URL: '%s', File: %s, Offset(s) in File: \n" % (h, ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword URL: %s, File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as email_addr:
			text = email_addr.read()
			hits = re.findall(email, text, re.S)
			for h in hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					trommel_output.write("Plain/Non-Plain Text File, Keyword Email Address: '%s', File: %s\n" % (h, ff))
	except IOError:
		pass

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as seckey_keyword:
			text = seckey_keyword.read()
			hits = re.findall(secret_key_kw, text, re.I)
			if hits:
				magic_mime = magic.from_file(ff, mime=True)
				magic_hit = re.search(mime_kw, magic_mime, re.I)
				if magic_hit:
					offset_list = []
					for m in re.finditer(secret_key_kw, text, re.I):
						offset_list.append(m.start())
					trommel_output.write("Non-Plain Text File, Keyword Variation: 'secret key', File: %s, Offset(s) in File: \n" % (ff) + ", ".join('0x%x'%x for x in offset_list) + "\n")
				else:
					trommel_output.write("Plain Text File, Keyword Variation: 'secret key', File: %s, Keyword Hits in File: %d\n" % (ff, len(hits)))
	except IOError:
		pass


	if shell_script in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A shell script, File: %s\n" % (ff))


	if apache_bin in ff:
		trommel_output.write("Non-Plain Text File, Apache binary file: %s\n" % ff)

	if lighttpd_bin in ff:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as keyword_search:
			text = keyword_search.read()
			lt_term = 'lighttpd/[0-9]{1}\.[0-9]{1,2}\.[0-9]{1,2}'
			lt_hit = re.search(lt_term, text)
			if lt_hit:
				trommel_output.write("The lighttpd binary found is %s\n" % lt_hit.group())

	if httpd_bin in ff:
		trommel_output.write("Non-Plain Text File, httpd binary file: %s\n" % ff)

	if config_1 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A configuration file (.conf), File: %s\n" % (ff))

	if config_2 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A configuration file (.cfg), File: %s\n" % (ff))


	if config_3 in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A configuration file (.ini), File: %s\n" % (ff))
		trommel_output.write("A .ini configuration file: %s\n" % ff)

	if db_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A database file (.db), File: %s\n" % (ff))

	if sqlite_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A database file (.sqlite), File: %s\n" % (ff))

	if sql_file in ff:
		magic_mime = magic.from_file(ff, mime=True)
		magic_hit = re.search(mime_kw, magic_mime, re.I)
		if magic_hit:
			trommel_output.write("Plain/Non-Plain Text File, A database file (.sql), File: %s\n" % (ff))

	
	if php_fn in ff:
		read_search_case_kw(ff, php_server_func, trommel_output)
		read_search_case_kw(ff, php_get_func, trommel_output)
		read_search_case_kw(ff, php_post_func, trommel_output)
		read_search_case_kw(ff, php_request_func, trommel_output)
		read_search_case_kw(ff, php_files_func, trommel_output)
		read_search_case_kw(ff, php_cookie_func, trommel_output)
		read_search_case_kw(ff, php_split_kw, trommel_output)

		read_search_case_kw(ff, php_sql_com1, trommel_output)
		read_search_case_kw(ff, php_sql_com2, trommel_output)
		read_search_case_kw(ff, php_sql_com3, trommel_output)

		read_search_kw(ff, php_shellexec_func, trommel_output)
		read_search_kw(ff, php_exec_func, trommel_output)
		read_search_kw(ff, php_passthru_func, trommel_output)
		read_search_kw(ff, php_system_func, trommel_output)

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as js_file:
			text = js_file.read()
			hits = re.findall(script_word, text, re.S)
			if hits:
				read_search_kw(ff, alert_kw, trommel_output)
				read_search_kw(ff, src_kw, trommel_output)
				read_search_kw(ff, script_kw, trommel_output)
				read_search_kw(ff, script1_kw, trommel_output)
				read_search_case_kw(ff, doc_url_kw, trommel_output)
				read_search_case_kw(ff, doc_loc_kw, trommel_output)
				read_search_case_kw(ff, doc_referrer_kw, trommel_output)
				read_search_case_kw(ff, win_loc_kw, trommel_output)
				read_search_case_kw(ff, doc_cookies_kw, trommel_output)
				read_search_case_kw(ff, eval_kw, trommel_output)
				read_search_case_kw(ff, settimeout_kw, trommel_output)
				read_search_case_kw(ff, setinterval_kw, trommel_output)
				read_search_case_kw(ff, loc_assign_kw, trommel_output)
				read_search_case_kw(ff, nav_referrer_kw, trommel_output)
				read_search_case_kw(ff, win_name_kw, trommel_output)
	except IOError:
		pass

	read_search_kw(ff, vbscript_kw, trommel_output)

	if lua_fn in ff:
		read_search_lua_kw(ff, lua_get, trommel_output)
		read_search_lua_kw(ff, lua_cgi_query, trommel_output)
		read_search_lua_kw(ff, lua_cgi_post, trommel_output)
		read_search_lua_kw(ff, lua_print, trommel_output)
		read_search_lua_kw(ff, lua_iowrite, trommel_output)
		read_search_lua_kw(ff, lua_ioopen, trommel_output)
		read_search_lua_kw(ff, lua_cgi_put, trommel_output)
		read_search_lua_kw(ff, lua_cgi_handhelp, trommel_output)
		read_search_lua_kw(ff, lua_execute, trommel_output)
		read_search_lua_kw(ff, lua_strcat, trommel_output)
		read_search_lua_kw(ff, lua_htmlentities, trommel_output)
		read_search_lua_kw(ff, lua_htmlspecialchars, trommel_output)
		read_search_lua_kw(ff, lua_htmlescape, trommel_output)
		read_search_lua_kw(ff, lua_htmlentitydecode, trommel_output)
		read_search_lua_kw(ff, lua_htmlunescape, trommel_output)
		read_search_lua_kw(ff, lua_iopopen, trommel_output)
		read_search_lua_kw(ff, lua_escapeshellarg, trommel_output)
		read_search_lua_kw(ff, lua_unescapeshellarg, trommel_output)
		read_search_lua_kw(ff, lua_escapeshellcmd, trommel_output)
		read_search_lua_kw(ff, lua_unescapeshellcmd, trommel_output)
		read_search_lua_kw(ff, lua_fhupo, trommel_output)
		read_search_lua_kw(ff, lua_fhpo, trommel_output)
		read_search_lua_kw(ff, lua_fsppo, trommel_output)
		read_search_lua_kw(ff, lua_ntopreaddir, trommel_output)


	
	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as file:
			text = file.read()
			hits = re.findall(perm, text, re.S)
			for h in hits:
				trommel_output.write("Found a file that contains a Android permission: %s : %s\n" % (ff, h))
	except IOError:
		pass

	try:
		with codecs.open(ff, 'r', encoding='utf-8', errors='ignore') as file:
			text = file.read()
			hits = re.findall(pkg_name, text, re.S)
			for h in hits:
				trommel_output.write("Found a file that contains a Android package/app name: %s : %s\n" % (ff, h))
	except IOError:
		pass