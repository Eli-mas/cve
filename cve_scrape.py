import sys, os, pickle, re
from io import StringIO
from functools import reduce
#from pathlib import Path
import argparse

import requests
#import requests_html
#from bs4 import BeautifulSoup as bs
import numpy as np
import pandas as pd
#from matplotlib import pyplot as plt

from cve_thread import _ThreadDistributedResponseRetriever, ChunkedRetriever
import cve_core
from cve_core import EDB_TABLE_PATH
from cve_process import get_full_table

#whitespace = re.compile('\W{2,}')
#PRODUCT_PATTERN = re.compile('(?<=cvedetails.com/product/)\d+')
CVE_ID_URL = "https://www.cvedetails.com/cve/{}/"

class CVERetriever(_ThreadDistributedResponseRetriever):
	def __init__(self,urls=None,limit=None,span=None,**kw):
		if urls is None:
			urls = get_full_table()['CVE ID'].values
		if span: urls=urls[span]
		elif limit: urls=urls[:limit]
		super().__init__(urls, **kw)
	
	def process_content(self,response):
		return get_affected_product_summary(response, raise0=False)
	
	def format_url(self,url):
		return CVE_ID_URL.format(url)

class ChunkedCVERetriever(ChunkedRetriever, CVERetriever):
	
	def __init__(self,*a,**kw):
		super().__init__(*a, path='cve affected products', **kw)

def get_affected_product_summary(response=None, _id=None, raise0=True):
	if response is None:
		response = requests.get(CVE_ID_URL.format(_id))
	tables = pd.read_html(StringIO(response.content.decode('utf-8')))
	tables = [
		t for t in tables if
			isinstance(t.columns[-1],str) and
			t.columns[-1]=='Vulnerable Versions'
	]
	if len(tables)>1:
		raise ValueError('ambiguous result for affected product table at id {_id}')
	
	if len(tables)==0:
		if raise0:
			raise ValueError('cve affected product search: no matching tables found')
		return 0
	
	return tables[0]['Vulnerable Versions'].values.sum()

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-l','--limit',type=int,default=200)
	parser.add_argument('-c','--chunksize',type=float, default=None)
	parser.add_argument('-n','--chunks',type=int,default=10)
	parser.add_argument('-s','--span',type=str)
	parser.add_argument('-v','--verbosity',type=int, default=0)
	parser.add_argument('-t','--threads',type=int, default=30)
	args = parser.parse_args()
	
	try: span = range(*map(int, args.span.split(':')))
	except: span = None
	limit = args.limit
	print(span,limit,args.chunksize,args.chunks)
	r = ChunkedCVERetriever(
		limit=limit, span=span, threads=args.threads,
		chunksize = args.chunksize, chunks=args.chunks,
		verbosity=args.verbosity
	)
	r.assign_expected_error(ValueError, True)
	r.retrieve()
	#sys.exit()
	
	folders_path = 'chunks/cve affected products'
	
	folder = os.listdir(folders_path)
	
	folder = max(filter(lambda f: os.path.isdir(f'{folders_path}/{f}'), folder), key = lambda f: float(f))
	path = f'{folders_path}/{folder}'
	f = sorted((f for f in os.listdir(path) if f.startswith('chunk')), key = lambda f: int(f.split()[1]))
	print('folder',folder)
	print(f)
	
	def get(p):
		with open(f'{path}/{p}','rb') as f:
			l=pickle.load(f)
		
		return l
	
	full = np.array(get(f[0]))
	joined = np.array(reduce(list.__add__, map(get,f[1:])))
	
	print(full.shape)
	print(joined.shape)
	
	if not(np.array_equal(full,joined)):
		off = full!=joined
		print(np.where(off))
		print(full[off])
		print(joined[off])
	else:
		print('results are equal')
	print('None counts:',sum(v is None for v in full),sum(v is None for v in joined))