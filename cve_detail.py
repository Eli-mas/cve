import os, re, requests, time, threading
from io import StringIO
import numpy as np, pandas as pd

from cve_core import *
from cve_process import get_full_table

PRODUCT_PATTERN = re.compile('(?<=cvedetails.com/product/)\d+')
CVE_ID_URL = "https://www.cvedetails.com/cve/{}/"
VERBOSE = True
ERRORS = []
ERROR_AGENTS = []
TOTAL_ERROR_COUNT = 0

def get_affected_products(cve_id,ua=None):
	"""
	cve_id matches CVE-YYYY-\d+
	example: CVE-2003-1564
	"""
	if VERBOSE: print_update(cve_id)
	url = CVE_ID_URL.format(cve_id)
	
	if ua: r = requests.get(url,headers={'User-Agent':ua})
	else: r = requests.get(url)

	try:
		r.raise_for_status()
		return np.unique([int(m.group()) for m in PRODUCT_PATTERN.finditer(r.content.decode('utf-8'))])
	except HTTPError:
		if VERBOSE: print_update(f'ERROR: {cve_id}\n')
		ERRORS.append(cve_id)
		ERROR_AGENTS.append(ua)
		global TOTAL_ERROR_COUNT
		TOTAL_ERROR_COUNT += 1
		if TOTAL_ERROR_COUNT>100: raise ThresholdExceededError(100)

def get_affected_products_from_ids(ids,user_agents=None):
	t0=time.time()
	if user_agents is None:
		r = [get_affected_products(id) for id in ids]
	else:
		if isinstance(user_agents,bool):
			user_agents = get_user_agents()
		r = [get_affected_products(id,ua) for id,ua in zip(ids,shuffle_return(user_agents))]
	elapsed=time.time()-t0
	if VERBOSE: print_update('')
	print(elapsed)
	return r

if __name__=='__main__':
	from cve_detail import *
	#ids = [f'CVE-2003-{i:04d}' for i in range(1500)]
	ids = get_full_table()['CVE ID'].str.upper().values
	p = get_affected_products_from_ids(ids[::100], user_agents=True)
	print(ERRORS)