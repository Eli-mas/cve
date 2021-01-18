import time, sys, io, os
import requests
import re
import threading
from threading import RLock
from queue import Queue, Empty
import numpy as np
import pandas as pd
from cve_core import *

def print_update(*p):
	print('\x1b[2K\r',*p,flush=True,end='')

def shuffle_return(l):
	np.random.shuffle(l)
	return l

TABLE_PATH = 'tables/{}.csv'
def table_saver(df,page_number):
	df.to_csv(TABLE_PATH.format(page_number))
def check_already_downloaded(page_number):
	return os.path.exists(TABLE_PATH.format(page_number))

THREAD_COUNT = 10
PAGE_NUMBER_PATTERN = re.compile('(?<=page=)\d+?(?=[&])')
PAGE_PATTERN = re.compile('vulnerability-list[.]php[?]vendor_id=\d{,1}[&]product_id=\d{,1}[&]version_id=\d{,1}[&]page=\d+?[&].+?(?=")')
COLUMNS = [
	'#', 'CVE ID', 'CWE ID', '# of Exploits', 'Vulnerability Type(s)',
	'Publish Date', 'Update Date', 'Score', 'Gained Access Level', 'Access',
	'Complexity', 'Authentication', 'Conf.', 'Integ.', 'Avail.',
]
PAGE_ERROR_THRESHOLD = 3
TOTAL_ERROR_THRESHOLD = np.inf #10 #set to inf for no limit
TIMER = []


def get_table_from_page(url=None,content=None,ua=None):
	if content is None:
		if not url.startswith('https'): url = f'https://www.cvedetails.com/{url}'
		
		if ua: r = requests.get(url,headers={'User-Agent':ua})
		else: r = requests.get(url)
		
		if r.status_code != 200:
			page = re.search(PAGE_NUMBER_PATTERN, url).group()
			raise RuntimeError(
				f'error on page={page} (reponse status code: {r.status_code}); '
				f'posting to queue to try again: url={url}')
		
		content = r.content
		tables = pd.read_html(io.StringIO(content.decode('utf-8')))
	else: tables = pd.read_html(io.StringIO(content))
	t = [t for t in tables if 'CVE ID' in t.columns]
	if len(t)>1:
		raise ValueError('more than one matching table found on page '
						 f'{PAGE_NUMBER_PATTERN.search(url).group()}')
	t=t[0][COLUMNS]
	
	tfields = t.iloc[::2].copy(deep=True)
	
	#if tdesc.shape!=tfields.shape:
	#	raise ValueError('table fields and descriptions have unmatching lengths: '
	#					 f'{tfields.shape}, {tdesc.shape}')
		
	tfields['desc'] = t['#'].iloc[1::2].values
	
	return tfields

def get_cve_urls():
	print('retrieving cve urls...')
	url_main = 'https://www.cvedetails.com/vulnerability-list/'
	r = requests.get(url_main)
	data = r.content.decode('utf-8')
	if r.status_code != 200:
		with open("cve_err.out",'w') as f: f.write(data)
		raise RuntimeError(f"'get_cve_urls': response code = {r.status_code}; see 'cve_err.out' for html response")
	page_urls = [m.group() for m in PAGE_PATTERN.finditer(data)]
	
	p2_index=0
	try:
		while 'page=1' in page_urls[p2_index]: p2_index += 1
		del page_urls[:p2_index-1]
		
		return page_urls, data
	except IndexError:
		print('*** Error encountered: printing first 20 urls then re-raising; check file "cve_err.out" for html response ***')
		with open("cve_err.out",'w') as f: f.write(data)
		for l in page_urls[:20]: print(l)
		raise

def get_tables_from_pages(page_urls):
	...

class CVERetriever:
	def __init__(self):
		self.in_memory = False
	
	def increment_total_error(self):
		self.lock.acquire()
		self.total_error += 1
		self.lock.release()
	
	def increment_page_error(self,page):
		self.lock.acquire()
		self.errors[page]+=1
		self.lock.release()
	
	def set_urls(self):
		self.urls, data = get_cve_urls()
		self.tables = [None] * len(self.urls)
		self.user_agents = get_user_agents(len(self.urls))
		if not check_already_downloaded(1): self.set_table(1,content=data)
		self.queue = Queue()
		self.threads = [
			threading.Thread(target=self.set_table_from_queue)
			for _ in range(THREAD_COUNT)
		]
		self.lock = threading.RLock()
	
	def set_table(self,page_number,content=None):
		index = page_number-1
		table = get_table_from_page(self.urls[index],
												 ua=self.user_agents[index],
												 content=content)
		if self.in_memory: # store in active memory
			self.tables[index] = table
		else: # save table to disk
			table_saver(table,page_number)
		
	def print_ETR(self):
		elapsed_time = time.time() - TIMER[0]
		try:
			etr = round((elapsed_time/self.processed)*(self.size-self.processed),1)
		except ZeroDivisionError:
			etr = '--'
		print_update(#f'{threading.get_ident()}: setting table from page {page} '
					 f'count={self.processed}/{self.size}, '
					 f'time elapsed = {elapsed_time:.1f}, '
					 f'ETR = {etr}, '
					 f'errors: {sum(self.errors.values())}')
	
	def increment_processed(self):
		self.lock.acquire()
		self.processed+=1
		self.lock.release()
	
	def set_table_from_queue(self):
		try:
			while True:
				if self.canceled: break
				
				if self.total_error>TOTAL_ERROR_THRESHOLD:
					raise RuntimeError('total error threshold exceeded')
				try:
					count,page = self.queue.get_nowait()
					self.set_table(page)
					self.increment_processed()
				
				except Empty: break
				
				except RuntimeError as e:
					self.increment_page_error(page)
					if self.errors[page]>PAGE_ERROR_THRESHOLD:
						self.failed_pages.append((page,repr(e)))
						self.increment_processed()
						break
					else:
						self.queue.put((count,page))
				
				time.sleep(round(7*np.random.random()+3, 3))
				# random value between 3 and 10, round -> 3 decimal placs
		except KeyboardInterrupt:
			self.canceled = True
	
	def set_tables(self,lim1=None,lim2=None,low=None,high=None,pages=None):
		self.set_urls()
		
		if pages is None: #grab pages within bounds of [low, high]
			if low is None and high is None:
				if lim2 is None:
					if lim1 is None: low, high = 1, len(self.urls)
					else: low, high = 1, lim1
				else:
					low, high = lim1, lim2
			else:
				if high is None: high=len(self.urls)
			self.low, self.high = low, high
			self.errors = {i:0 for i in range(low,high)}
			self.failed_pages = []
			self.total_error = 0
			self.size = high - low
			
			count=0
			for page_number in shuffle_return(np.arange(low,high+1)):
				if not check_already_downloaded(page_number):
					self.queue.put((count,page_number))#
					count += 1
			
			print('low, high:',low,high)
			print('actual count:',count)
			print('\t(Note: skipping pages where tables already downloaded)')
			
		else: # grab specified pages
			self.pages = pages
			self.size = len(pages)
			
			for i,page_number in enumerate(pages):
				self.queue.put((i,page_number))#
		
		"""print('iterating over pages')
		low, high = np.inf, 0
		while True:
			try:
				i,p = self.queue.get_nowait()
				low=min(low,p)
				high=max(high,p)
				#print((i,p))
			except Empty:
				break
		print('low, high:', low, high)
		print('finished iterating over pages; exiting')
		sys.exit()"""
		
		if count:
			self.running=True
			self.processed=0
			TIMER.append(time.time())
			
			for t in self.threads: t.start()
			
			print_thread = threading.Thread(target=self.update_time)
			print_thread.start()
			
			for t in self.threads: t.join()
			
			self.running=False
			
			print(f'\nfinished; errors:<<<\n')
			for k,v in self.errors.items():
				if v: print(k, v)
			print('>>>')
			for page,err in self.failed_pages: print(f'{page}:\n{err}')
		else:
			print('no pages to process; exiting')
		
		#self.complete_table = pd.concat(self.tables[low:high])
		#
		#print('total process time:',time.time()-TIMER[0])
		#
		#return self.complete_table
	
	def update_time(self):
		while self.running:
			if self.canceled:
				print('cancelling threads, wait a few moments...')
			
			if self.processed>3 or sum(self.errors.values()):
				self.print_ETR()
			
			time.sleep(1)
		
		print_update('')
				

if __name__=='__main__':
	t = CVERetriever().set_tables(low=2000)

