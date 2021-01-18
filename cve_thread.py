import time, sys, io, os, copy
import math
import packaging
import pickle
from itertools import takewhile
from collections import namedtuple
import requests
import threading
from threading import Thread, RLock, Condition, Event, current_thread
from queue import Queue, Empty
import pandas as pd
import numpy as np
#import re
from bs4 import BeautifulSoup as bs
from requests.exceptions import SSLError
from functools import partial, wraps

import cve_core
from cve_core import *

	
def wait(condition,check, *a, **kw):
	with condition:
		while not check(*a,**kw):
			condition.wait()

def notify(condition):
	with condition: condition.notify()

def empty_queue(q):
	results = []
	while True:
		try: results.append(q.get_nowait())
		except Empty: break
	return results

# for each error resopnse code, whether or not it should be repeated
# if True, we should look to have values be numbers indicating the max # of repeats to try
status_repeat={
	400: False,		# Uniterpretable request -- never repeat
	401: False,		# Unauthorized
	402: False,		# Payment required
	403: True,		# Refused -- try repeating later with different conditions (e.g. different user agent, different load)
	404: False,		# No matching resource found, or found but secretly denied -- do not repeat
	405: False,		# Invalid method, e.g. a GET where a POST should have been sent
	407: False,		# Request requires Proxy authentication; similar to 401
	408: True,		# Timeout
	409: False,		# Conflict with current resource state
	410: False,		# Gone
	411: False,		# Length Required
	412: False,		# Precondition Failed
	413: True,		# Request Entity Too Large
	414: False,		# Request-URI Too Long
	415: False,		# Unsupported Media Type
	416: False,		# Requested Range Not Satisfiable
	417: False,		# Expectation Failed
	#418: ,		#  I'm a teapot (RFC 2324)
	420: True,		# Enhance Your Calm (Twitter)
	422: False,		# Unprocessable Entity (WebDAV) [semantic errors in syntatically correct request]
	423: False,		# Locked (WebDAV)
	424: False,		# Failed Dependency (WebDAV)
	425: False,		# Reserved for WebDAV
	426: False,		# Upgrade Required
	428: False,		# Precondition Required
	429: True,		# Too Many Requests
	431: False,		# Request Header Fields Too Large
	444: False,		# No Response (Nginx)
	449: False,		# Retry With (Microsoft)
	450: False,		# Blocked by Windows Parental Controls (Microsoft)
	451: False,		# Unavailable For Legal Reasons
	499: False,		# Client Closed Request (Nginx)
	500: True,		# Internal Server Error
	501: False,		# Not Implemented
	502: True,		# Bad Gateway
	503: True,		# Service Unavailable
	504: True,		# Gateway Timeout
	505: False,		# HTTP Version Not Supported
	506: False,		# Variant Also Negotiates (Experimental)
	507: True,		# Insufficient Storage (WebDAV)
	508: False,		# Loop Detected (WebDAV)
	509: True,		# Bandwidth Limit Exceeded (Apache)		# ???
	510: False,		# Not Extended
	511: False,		# Network Authentication Required
	598: True,		# Network read timeout error
	599: True,		# Network connect timeout error
}


class UrlBundle:
	def __init__(self, index, url_item, url, response=None):
		self.index = index
		self.item = url_item
		self.url = url
		self.response=response
	
	def set_response(self,r): self.response=r
	def get_response(self): return self.response
	def get_url(self): return self.url
	def get_item(self): return self.item
	def get_index(self): return self.index
	def get(self): return self.index, self.item, self.url, self.response

class UrlBundler:
	def __init__(self,items,urls):
		self.items = items
		self.urls = urls
		self.size = len(urls)
		self.responses = [None] * self.size
	
	def get(self, index):
		return UrlBundle(index, self.items[index], self.urls[index], self.responses[index])

class _BasePolicy:
	"""
	like a namedtuple, but do not have to specify all attributes upon initialization
	"""
	_defaults = NotImplemented # dict: properties of the cooperating class
	__slots__ = () # tuple: keys in properties
	
	#def __init__(self)

	def __init__(self, **kw):
		self.assign(**{**self._defaults,**kw})
	
	def assign(self, **kw):
		self.set(kw.keys(),kw.values())
	
	def set(self, names, values):
		#self.assign(**dict(zip(names,values)))
		#unrecognized = []
		for k,v in zip(names, values):
			try: setattr(self,k,v)
			except AttributeError: pass #unrecognized.append(k)
		#if unrecognized:
		#	print('unrecognized keywords passed to Policy.assign are being ignored:',unrecognized)
	
	def reset(self, names):
		self.set(self._defaults.keys(), self._defaults.values())
	
	def dump(self):
		return {k:getattr(self,k) for k in self._defaults}
	
	def inherit(self,other,*keys):
		"""
		inherit key values from another Policy or mapping
		"""
		if not keys: keys = self.keys()
		self.set(keys, (other[k] for k in keys))
	
	def keys(self): return self._defaults.keys()
	def __getitem__(self,key): return self._defaults[key]

def make_policy(name,**defaults):
	return type(
		name,
		(_BasePolicy,),
		{'_defaults':defaults,'__slots__':tuple(defaults.keys())}
	)

PrimaryPolicy = make_policy('PrimaryPolicy',
	in_memory = False,
	thread_count = 10,
	expected_errors = None,
	err_threshold  = 4,
	total_err_threshold = 100, # np.inf #set to inf for no limit
	ua_exclude = None,
	sleep_range= None,
	count_time = True,
	test_conn_err = False,
	timeout = 10, # timeout in call to requests.get, in seconds
	verbosity = 0, # higher verbosity levels control output
	backoff = 1,	# 'backoff' can be the 'form' argument to __set_backoff_policy,
					# or a mapping (Policy or dict) for all the other arguments
	bad_status_threshold = 100, # permitted number of bad status codes
	conn_err_wait = 5*60, # 5 minutes : time spent waiting after connection error
	conn_err_inc = 5*60 # increment to the connection error wait every time one occurs
)

class PolicyCooperator:
	"""
	other classes in this module should inherit from this class
	features of this class:
		it has an associated type which is a subclass of Policy
		it has a property method for each field of the Policy class,
			assigned programatically via ineraction with the Policy class or instance
	"""
	
	def _pget(self,attr):
		#print('_pget:',attr)
		return getattr(self.policy, attr)
	
	def _pset(self,value,attr):
		setattr(self.policy,attr,value)
	
	def __init__(self,policy): self.policy = policy
	
	#def __new__(cls, **kw):
	#	print('__new__ args:',kw)
	#	print('__new__ args:',cls)
	#	x = super().__new__(cls)
	#	print('__new__ object to be returned from:',x,'of class',type(x))
	#	print(x.get_ptype())
	#	
	#	
	#	
	#	return x
	
	def get_ptype(self): return self._PTYPE

def associate_policy_with_cooperator(ctype, ptype=None):
	if ptype is None: ptype = ctype._PTYPE
	for key in ptype._defaults:
		prop = property(partial(ctype._pget,attr=key))
		setter = prop.setter(partial(ctype._pset,attr=key))
		setattr(ctype,key,prop)
		setattr(ctype,key,setter)

#print('about to define TestCooperator')
class TestCooperator(PolicyCooperator):
	_PTYPE = PrimaryPolicy
	
	def __init__(self,**kw):
		self.policy = self._PTYPE(**kw)
		print(self.policy.dump())
		print('attributes by self reference:')
		for attr in ('count_time','in_memory'):
			print(f'\t{attr}: {getattr(self,attr)}')
#print('defined TestCooperator')
associate_policy_with_cooperator(TestCooperator)

class RetrieverCooperator(PolicyCooperator):#
	_PTYPE = PrimaryPolicy
	
	def __init__(self,retriever):
		self.retriever = retriever
		super().__init__(retriever.policy)
	
	#@wraps(Printer.print)
	def print(self,*a,**kw): self.retriever.printer.print(*a,**kw)
	#@wraps(Printer.vprint)
	def vprint(self,*a,**kw): self.retriever.printer.vprint(*a,**kw)

associate_policy_with_cooperator(RetrieverCooperator)

class Printer(RetrieverCooperator):
	
						################							################
	################################		PRINTING FUNCTIONS			################################
						################							################
	def __init__(self, retriever, verbosity=None, count_time=True):
		super().__init__(retriever)
		#if verbosity is not None: self.verbosity = verbosity
		#self.count_time = count_time
		self.print_lock = RLock()
		self.print_thread = Thread(target = self.update_time)
		self.started=False
		self.finished=False
	
	def print(self, *a, **kw):
		with self.print_lock:
			if (self.started ^ self.finished):
				if self.count_time: print('\n\n')
				print(*a, **kw)
				if self.count_time: print('\n')
			else:
				print(*a, **kw)
	
	def vprint(self,*a,v=None,**kw):
		if v is None or v<=self.verbosity:
			self.print(*a,**kw)
	
	#def print_start():
	#	print_condition = Condition()
	
	def update_time(self):
		print('starting print thread')
		while self.retriever.running:
			try:
				if self.retriever.get_num_processed()>3 or self.retriever.get_err_count():
					self.print_ETR()
			except Exception as e:
				self.print(
					'** ERROR in `update_time`: traceback follows, '
					f'exiting print loop\n*\t*\t*\t*\n{repr(e)}')
				break
			time.sleep(1)
	
	def print_ETR(self):
		elapsed_time = time.time() - self.retriever.start_time
		self.elapsed_time = elapsed_time
		
		x, xt = self.retriever.get_rt_ratios()
		num_processed = self.retriever.get_num_processed()
		size = self.retriever.size
		
		try:
			etr = round((elapsed_time/num_processed)*(size-num_processed),1)
		except ZeroDivisionError:
			etr = '--'
		
		with self.print_lock:
			print_update(#f'{threading.get_ident()}: setting table from page {page} '
					 f'count = {num_processed}/{size}, '
					 f'time elapsed = {elapsed_time:.1f}, '
					 f'ETR = {etr}, '
					 f'r/e = {x:.4f} --> {xt:.4f}, ',
					 f'errors: {self.retriever.get_err_count()} '
					 f'failed: {self.retriever.get_failed_count()} '
					 f'bad_status: {self.retriever.get_bad_status_count()}')
	
	def start(self):
		if self.count_time:
			self.started=True
			self.print_thread.start()
	
	def join(self):
		if self.count_time:
			self.print_thread.join()
			self.finished=True

class TimingManager(RetrieverCooperator):
	"""
	manages request delays/timing for retriever classes
	
	to do:
		incorporate https://docs.python.org/3.7/library/urllib.robotparser.html
		
		make this class realize when certain websites don't need to be delayed--
		e.g. if a given domain www.domain.com/... has not been visited before,
		then there is no need to delay before processing it, as it won't deny the request
		do to high volume from this source -- unless ISP is throttling
			solution:
				keep track of average time per domain
					and perhaps a different sleep range for each domain,
					and let each thread sleep for a time computed
					based on the url it is about to request
				
				also keep track of a global average response time
				(across all domains), so that in case ISP
				is throttling we can slow down
		
		see notes at calculate_sleep_time_for_url
	"""
	__SLEEP_RANGE = (2,8)
	
	#@wraps(Printer.print)
	#def print(self,*a,**kw): self.printer.print(*a,**kw)
	#@wraps(Printer.vprint)
	#def vprint(self,*a,**kw): self.printer.vprint(*a,**kw)
	
	def get_rt_ratios(self):
		return self.response_time_ratio, self.response_time_ratio_transformed
	
	def __init__(self, retriever):#, sleep_range=None
		super().__init__(retriever)
		sleep_range = self.sleep_range
		if sleep_range is not None:
			try:
				low, high = sleep_range
				
				if low >= high:
					raise ValueError(f'low ({low}) must be less than {high}')
				
				if low < 2:
					raise ValueError(f'low ({low}) must be at least 2')
				
			except Exception as e:
				self.sleep_start, self.sleep_interval = self.__SLEEP_RANGE
				
				self.print(
					f"exception caught in processing parameter 'sleep_range'={sleep_range}"
					f', error={repr(e)}--'
					'make sure you specify an ordered iterable of two numeric values; '
					f'defaulting to values ({self.sleep_start}, {self.sleep_interval});'
				)
		else:
			low, high = self.__SLEEP_RANGE
				
		self.sleep_start, self.sleep_interval = low, high-low
			
		self.default_sleep_start, self.default_sleep_interval = \
			self.sleep_start, self.sleep_interval
		
		self.__set_backoff_policy(1) # default is linear backoff with coefficient 1
			
		self.early_response_time_marker = -2
		
		self.printer = retriever.printer
		self.retriever = retriever
		
		self.response_time_list_lock = RLock()
		self.response_time_lock = RLock()
		self.recent_response_times = []
		self.__early_response_time = self.__recent_response_time = np.nan
		self.response_time_ratio = np.nan
		self.response_time_ratio_transformed = np.nan
	
	@property
	def thread_count(self): return self.retriever.thread_count
	
	def get_sleep_time(self,url=None):
		if url is None: return self.get_random_sleep_time()
		else: return self.calculate_sleep_time_for_url(url)
		
	def calculate_sleep_time_for_url(self,url):
		...
		"""
		finish: when urls from different domains come in, process accordingly
		an idea is to have a (linked) list or something equivalent, which tells
		recently visited domains, and a dictionary to tell the (average) time(s)
		for domains; periodically (every call or some interval of calls, or some time frame)
		the list will purge the domains that were not visited recently,
		which get deleted from the dictionary
		
		also will have to take into account robots.txt
		
		see notes at class opening
		
		use <from urllib.parse import urlparse>, urlparse(url).netloc to get domain
		"""
		return self.get_random_sleep_time()
	
	def get_random_sleep_time(self):
		return self.sleep_start+np.random.random()*self.sleep_interval
	
	def add_response_time(self,_time, index):
		self.vprint('adding response time:',_time, v=2)
		with self.response_time_list_lock:
			if len(self.recent_response_times)>=self.thread_count:
				self.__set_recent_response_time(index)
			self.recent_response_times.append(_time)
	
	def __set_recent_response_time(self, index):
		value = np.average(self.recent_response_times[:self.thread_count])
		self.vprint(f'**\tsetting response time due to list size: {value}', v=2)
		with self.response_time_lock:
			if self.early_response_time_marker:
				self.vprint(f'***\t\tsetting early response time: {value}', v=2)
				self.__early_response_time = value
				self.early_response_time_marker += 1
			else:
				self.vprint(f'***\t\tsetting recent response time: {value}', v=2)
				self.__recent_response_time = value
				self.__adjust_sleep_window(index)
		del self.recent_response_times[:self.thread_count]
	
	def __check_availability_of_response_window(self,indices):
		return self.retriever.get_response_window_available(indices)
	#
	#def get_early_response_window(self):
	#	"""
	#	return the range(self.thread_count,2*self.thread_count),
	#	i.e. the window when each thread will have retrieved its second response
	#	"""
	#	return range(self.thread_count,2*self.thread_count)
	#
	#def __can_get_mean_time_of_early_responses(self):
	#	"""
	#	ensure that all threads in the early response window
	#	(see '__get_early_response_window') have delivered results
	#	"""
	#	# a more sophisticated check would have a timeout associated
	#	return self.__check_availability_of_response_window(self.get_early_response_window())
	#
	#def __set_mean_early_response_time(self):
	#	"""
	#	no need to wait here based on conditions--this is called
	#	inside of '__adjust_sleep_window', which is called
	#	after early response times are available
	#	"""
	#	
	#	
	#	with self.response_timer_condition:
	#		self.response_timer_condition.wait_for(__can_get_mean_time_of_early_responses)
	#	
	#	
	#	# then take the average
	#	self.mean_early_response_time = \
	#		np.mean(self.response_times[self.get_early_response_window()])
	#	
	#	self.early_response_time_set = True
	#
	def __get_mean_early_response_time(self):
		#self.__set_mean_early_response_time()
		#return self.mean_early_response_time
		return self.__early_response_time
	
	#def __notify_early_response_window_available(self):
	#	"""
	#	alert the thread waiting on availability of early response window
	#	the the window is available
	#	"""
	#	with self.response_timer_condition:
	#		self.response_timer_condition.notify()
	#
	#def __get_recent_response_window(self,index):
	#	return range(index-self.thread_count, index)
	#
	#def __can_get_mean_time_of_recent_responses(self,index):
	#	"""
	#	ensure that all threads in the recent response window
	#	(see '__get_recent_response_window') have delivered results
	#	"""
	#	# a more sophisticated check would have a timeout associated
	#	return self.__check_availability_of_response_window(self.__get_recent_response_window(index))
	#
	def __get_mean_recent_response_time(self,index):
		"""
		get the mean response time for the previous (self.thread_count) responses
		"""
		#check = partial(self.__can_get_mean_time_of_recent_responses,index=index)
		#
		#with self.recent_response_timer_condition:
		#	self.recent_response_timer_condition.wait_for(check)
		#	value = np.mean(self.response_times[self.get_early_response_window()])
		#
		return self.__recent_response_time
	#
	#def __notify_recent_response_window_available(self):
	#	"""
	#	alert the thread waiting on availability of recent response window
	#	the the window is available
	#	"""
	#	with self.recent_response_timer_condition:
	#		self.recent_response_timer_condition.notify()
	
	
	
	
	
						################							################
	################################		BACKOFF FUNCTIONS			################################
						################							################
	
	def __set_backoff_policy(self, form, coef=None, value=None):
		"""
		the backoff policy is the way the class responds to
		the average response time of requests; the sleep time
		for each thread is modified by an evaluator function that evaluates
		the recent mean response time in comparison to the early
		mean response time; the parameters for this function
		are used to construct that evaluator function.
		
		let 'x' = the ratio of recent mean response time to early mean response time,
		'low' = the default low end of the sleep time range,
		'range' = default high end of sleep time range
		
		Note:
			In current implementation,
			if x turns out to be less than 1, it is set to 1.
		
		the evaluator function returns m, where m depends on the parameters
		entered to this function
		
		after enough results have been collected, the time range is adjusted
		as follows: <new_low, new_high = m*low, m*low + m*range>. Thus where the
		original expected sleep time was low + range/2, the new expected sleep time
		is m*(low + range/2)
		
		::Parameters:: :
		parameters 'coef', 'value' have default values 1, 2
		
		if form is a string,
			'linear': m = coef * x
			'poly': m = coef * x**value
			'exp': m = coef * value**x
		
		if form is a callable, it will receive 'x' as its sole argument,
			and should return m
		
		if form is a numeric (int/float), then it is assumed that the evaluator is
		linear with 'form' interpreted as 'coef' would be if form='linear'
		
		"""
		if callable(form):
			func=form
		elif isinstance(form,str):
			if coef is None: coef=1
			if form=='linear':
				func = lambda x: coef*x
			else:
				if value is None: value=2
				if form=='poly':
					func = lambda x: coef * x**value
				elif form=='exp':
					func = lambda x: coef * value**x
		
		elif isinstance(form,(int,float)):
			func = lambda x: form * x
		
		self.__transform_backoff_coef = func
		# there is, in the future, the possibility
		# of dynamically (re)setting the policy and its parameters
		# based on AI-recommended tactics
		# based on analyses of response times
	
	def __adjust_sleep_window(self,index):
		low, span = self.default_sleep_start, self.default_sleep_interval
		recent,early = self.__get_mean_recent_response_time(index), self.__get_mean_early_response_time()
		x =  recent/early 
		m = self.__transform_backoff_coef(x)
		self.response_time_ratio = x
		self.response_time_ratio_transformed = m
		self.sleep_start, self.sleep_interval = m*low, m*(low+span)
		self.vprint(f'****\t\t\tindex={index} response time ratio = {x:.2f}, '
				   f'early={early:.2f} recent={recent:.2f}'
				   f' low, interval = ({self.sleep_start:.2f}, {self.sleep_interval:.2f})', v=1)
		
		#self.__adjust_sleep_ready=False
	
	#def is_time_to_adjust_sleep_interval(self):
	#	return self.__adjust_sleep_ready
	#
	#def sleep_interval_adjuster_loop(self):
	#	while self.running:
	#		self.__adjust_sleep_window()
	#
	#def start_sleep_adjuster_loop(self):
	#	self.sleep_adjuster_thread.start()

class MemoryManager(RetrieverCooperator):
	def __init__(self,retriever):
		super().__init__(retriever)
	"""
	this class, when developed, will manage memory for the retriever;
	in particular, it will monitor the retriever's memory dynamically
	(get an estimate of what each download size will be, then based on this
	check periodically to see what memory usage is and adjust estimates), and
	if there is a memory restriction imposed, it will force the retriever to
	stop until it can free up memory in some way
	"""
	pass

class DataManager(RetrieverCooperator):
	"""
	this class handles the data for the retriever:
		it stores the urls, user agents, etc.
		it also stores processed results
		it DOES NOT store the queue--this is the retriever's object
	
	NOTE: this class and other '<>Manager' classes should inherit
	from a common base class that has methods such as print,vprint defined
	"""
	def __init__(self,retriever,urls):
		super().__init__(retriever)
		self.__set_urls(urls)
		
	def get_start_time(self): return self.start_time
	
	def get_bad_status_responses(self):
		return self.bad_status
	
	@property
	def size(self): return self._size
	
	def __set_urls(self,url_items):
		"""
		set url_items, user agents, threads, attributes for handling errors,
		and then call `after_set_urls`.
		
		NOT to be overridden.
		"""
		# url items can contain objects of any types; the method
		# 'extract_url_from_queue_item' tells how to get a url from an item
		if len(url_items) != sum(1 for e in url_items):
			raise TypeError(
				"you passed in an unusual object where length(obj) differs from the "
				f"size of iter(obj): {len(url-items)}, {sum(1 for e in url_items)}; "
				'the object is of type {type(url_items)}. Passing this object into '
				'the retriever would lead to an indefinite hang.'
			)
		self.url_items = tuple(url_items)
		self._size = len(url_items)
		self.print(f'DataManager: size = {self.size}')
		
		self.__set_user_agents()
		self.ua_count = np.zeros(len(url_items),dtype=int) # counts how many times each user agent is used
		print('retrieved user agents')
		
		self.response_times = np.zeros(len(url_items),dtype=float)
		self.mean_response_times = np.nan
		
		self.processed_results = [None] * self.size
		
		
		#self.after_set_urls()
	
	def get_response_window_available(self,indices):
		return np.all(self.attempts[indices])
	
	#def after_set_urls(self):
	#	"""
	#	called after the urls are set in `__set_urls` method;
	#	default is to do nothing.
	#	"""
	#	pass
	
	def get_urls(self,format=False):
		if format:
			return [self.format_url(u) for u in self.url_items]
		return self.url_items
	
	def get_user_agents(self): return self.user_agents
	
	def __set_user_agents(self):
		"""
		set user-agents to be used when fetching pages
		
		NOT to be overridden.
		"""
		self.user_agents = get_user_agents(len(self.url_items),exclude=self.ua_exclude)
	
	def get_processed_results(self, index=False, filt=False):
		results = self.processed_results
		if index: results = enumerate(results)
		if filt: results = (r for p,r in zip(self.processed_results,results) if p is not None)
		return list(results)
	
	
	
	
						################							################
	################################			PREPROCESSING			################################
						################							################
	
	def format_url(self,url):
		"""
		defines an operation to perform on a url
		before submitting it to requests.get;
		this allows for url fragments to be stored in the queue
		for efficiency, and then expanded only when
		they are called upon.
		
		default is to do nothing, i.e. return the url as given
		"""
		return url
	
	def extract_url_from_queue_item(self,item_from_queue):
		"""
		since the queue can hold anything,
		have to specify how to get url out of a queue item
		
		default is that the queue items are the urls themselves
		"""
		return item_from_queue
	

class _ThreadDistributedResponseRetriever(PolicyCooperator):
	"""
	To do:
		handling different kinds of errors and status codes
		
		dynamically altering thread counts
		
		
		have sleep be performed BEFORE url requested, not after--
			this way the sleep time can be calculated based
			on the current url being processed
		
		make a new class: DataManager
			this class holds data on urls and requests, including attempts, bad_status,
			ua, etc.
			
			this can provide a common interface for different classes (Printer, TimingManager, etc.)
			to access this data
		
		currently there is one queue to which items are posted
			are there reasons for sustaining multiple queues?
	"""
	
	_PTYPE = PrimaryPolicy
	CONN_ERR_TEST_INDEX=150
	
	
	
						################							################
	################################	GETTERS/SETTERS/INCREMENTORS	################################
						################							################
	
	def __init__(self, urls, **kw):
		"""
		assign urls to this instance, establish a queue, and initialize other attributes
		
		NOTE: if overriding in subclass, be sure to call this method
		(_ThreadDistributedResponseRetriever.__init__) from within the overriding method
		"""
		
		self.policy = self._PTYPE(**kw)
		
		self.count_time = (self.count_time and (not self.verbosity) and (not self.test_conn_err))
		#self.test_conn_err = test_conn_err
		
		#if verbosity is not None: self.verbosity = verbosity
		self.printer = Printer(self, verbosity = self.verbosity, count_time = self.count_time)
		
		#self.err_threshold = err_threshold
		#self.total_err_threshold = total_err_threshold
		#if timeout is not None: self.timeout = timeout
		
		#self.thread_locks # use if a unique lock is required for each thread
		
		#	if self.expected_errors is not None:
		self.assign_expected_errors(self.expected_errors)
		#else:
		#	self.expected_errors=[]
		
		self.timing_manager = TimingManager(self)
		self.data_manager = DataManager(self,urls)
		
		self.queue = Queue()
		self.thread_count=min(self.thread_count,self.data_manager.size)
		self.__set_threads()
		print('threads set')
		
		self.failed=[] # tried several times and repeatedly failed with 403
		self.bad_status=[] # tried once and failed with code other than 403, e.g. 404
		self.unaccounted_exceptions=[] # error encountered that was not explicitly accounted for in code
		self.attempts = np.zeros(len(self.url_items),dtype=bool)
		
		self.errors = np.zeros(len(self.url_items),dtype=int) # counts how many errors experienced for each url
		self.success = np.zeros(len(self.url_items),dtype=bool) # succeeded after one or several tries
	
		self.total_error=0 # total # of errors across all attempts
	
# 	def __bad_stat_res(self)
# 		with self.queue_lock:
# 			self.bad_status_resolution()
# 	
# 	def bad_status_resolution(self):
# 		"""
# 		called when a thread encounters a non-403 failure error
# 		"""
# 		pass
	
	@property
	def size(self): return self.data_manager.size
	@property
	def url_items(self): return self.data_manager.url_items
	@property
	def user_agents(self): return self.data_manager.user_agents
	@property
	def ua_count(self): return self.data_manager.ua_count
	@property
	def response_times(self): return self.data_manager.response_times
	@property
	def processed_results(self): return self.data_manager.processed_results
	
	def get_processed_results(self,*a,**kw):
		return self.data_manager.get_processed_results(*a,**kw)
	
	
	def __set_threads(self):
		"""
		initialize the threads that will cycle through urls
		
		NOT to be overridden.
		"""
		self.threads = [
			Thread(target = self.scrape_loop, name=f't{_}')
			for _ in range(self.thread_count)
		]
		self.thread_names = [t.name for t in self.threads]
		
		self.err_counter_lock = RLock()
		self.success_counter_lock = RLock()
		self.queue_lock = RLock()
		self.ua_lock = RLock()
		self.connection_error_lock = RLock()
		#self.response_timer_lock = RLock()
		#self.recent_response_timer_lock = RLock()
		#self.sleep_interval_adjuster_lock = RLock()
		
		self.connection_waits={n:0 for n in self.thread_names}
		#self.__CONN_ERR_WAIT = self.__DEFAULT_CONN_ERR_WAIT
		#self.__CONN_ERR_INC = self.__DEFAULT_CONN_ERR_INC
		self.__waiting_for_connection_sleep=False
		
		#self.sleep_adjuster_thread = Thread(target=self.sleep_interval_adjuster_loop)
		
		#self.early_response_time_event = Event()
		
		self.connection_wait_condition = Condition(self.connection_error_lock)
		#self.response_timer_condition = Condition(self.response_timer_lock)
		#self.recent_response_timer_condition = Condition(self.recent_response_timer_lock)
		#self.sleep_interval_adjuster_condition = Condition(self.sleep_interval_adjuster_lock)
	
	def get_thread_count(self):
		return self.thread_count
	
	@wraps(TimingManager.get_rt_ratios)
	def get_rt_ratios(self): return self.timing_manager.get_rt_ratios()
	
	def get_err_count(self): return sum(self.errors)
	
	def get_failed_count(self): return len(self.failed) + len(self.unaccounted_exceptions)
	
	def get_bad_status_count(self): return len(self.bad_status)
	
	def get_num_processed(self): return self.num_items_processed
	
	def __increment_ua_count(self, index):
		"""increment the # of times the user agent at this index has been used"""
		with self.ua_lock:
			self.ua_count[index] += 1
		
	def __increment_processed(self):
		with self.success_counter_lock:
			self.num_items_processed+=1
	
	def __increment_error(self,index):
		with self.err_counter_lock:
			self.errors[index] += 1
			self.total_error += 1
		
		if (self.total_error > self.total_err_threshold) or (self.errors[index] > self.err_threshold): #handle cases separately?
			raise ThresholdExceededError(
				self.err_threshold,
				'_DistributedUserAgentRetriever encoutered too many failures and is stopping retrievals'
			)
	
	
	
	
	
						################							################
	################################		ERROR EXPECTATION			################################
						################							################
	
	def __check_expected_error(self, error_class, fatal, action=None):
		"""
		assert that 'error_class' is an Exception
		and that 'action' is callable if provided
		"""
		assert issubclass(error_class,Exception), \
			f"'error_class' must inherit from Exception; {error_class} is not an Exception"
		
		# non-callable actions are permissible; handling the action parameter is not implemented
# 		if action is not None:
# 			assert callable(action), \
# 				f"'action' msut be callable if specified; {action} is not callable"
	
	def assign_expected_error(self, error_class, fatal, action=None):
		"""
		The loop that processes urls is set to handle raising of:
			HTTPError, from failing to fetch a webpaage;
			Empty, when the internal queue runs out;
			ThresholdExceededError, when a page fails too many times.
		
		If in the process, you expect that another error might be raised
		and want to catch it, provide it here.
		
		parameters:
		:: error_class ::	(type) class of the expected error, e.g. IndexError
		:: fatal ::	(bool) if this error occurs and 'fatal' is True, the page will be
					marked as a failure and not re-attempted. If False, the page
					will be tried until success or too many errors are encountered.
		:: action ::	(callable) action to be performed if the specified error is
						raised. This callable must have signature ? ? ? ?
		"""
		self.__check_expected_error(error_class, fatal, action)
		self.expected_errors.append((error_class,fatal,action))
	
	def assign_expected_errors(self,expected_errors):
		"""
		same as 'assign_expected_error', but for an iterable of expected errors.
		The iterable may be:
			--	a mapping, in which case each key should be an error type,
				and the values should be iterables of the form ( fatal[, action] )
			--	a conatiner iterable, in which each element should have the form
				( <error type>, fatal[, action] )
		"""
		if expected_errors is None:
			self.expected_errors=[]
			return
		try: # argument must be iterable
			iter(expected_errors)
		except TypeError:
			raise TypeError("non-iterable passed to 'assign_expected_errors' "
							f"when container iterable expected: {expected_errors}")
		
		if isinstance(expected_errors, dict):
			#assume dict has schema { <error type> : iterable( fatal[, action] ) }
			expected_errors = tuple((k,*v) for k,v in expected_errors.items())
		
		elif isinstance(expected_errors,str):
			# string is no good!
			raise TypeError("str passed to 'assign_expected_errors' "
							f"when container iterable expected: {expected_errors}")
		else: #any other cases to consider?
			pass
		
		#verify input
		for error_class,*other in expected_errors:
			self.__check_expected_error(error_class, *other)
		
		self.expected_errors.extend(expected_errors)
	
	
	
	
	
	
	
	
	
						################							################
	################################	CONNECTION ERROR HANDLING		################################
						################							################
	
	def __connection_sleep(self):
		with self.connection_wait_condition:
			start=time.time()
			time.sleep(self.conn_err_wait)#__CONN_ERR_WAIT
			end=time.time()
			self.vprint('the time from before to after the connection wait is',round(start-end,3),v=1)
			self.conn_err_wait += self.conn_err_in #self.__CONN_ERR_WAIT += self.__CONN_ERR_INC
			self.__waiting_for_connection_sleep=False
			connection_wait_condition.notify()
	
	def __set_connection_wait_thread(self):
		self.connection_thread_set = True
		self.connection_wait_thread = Thread(target=self.__connection_sleep)
	
	def __is_not_in_connection_wait(self):
		return not self.__is_in_connection_wait()
	
	def __is_in_connection_wait(self):
		return self.__waiting_for_connection_sleep
	
	def __on_connection_error(self):
		self.__waiting_for_connection_sleep=True
		self.__set_connection_wait_thread()
		self.connection_wait_thread.start()
	
	"""
	new methods to consider:
		do_not_process_url_from_response: a function that prevents url from being processed based on data retrieved from web
		do_not_process_url_before_response: a function that prevents url from being processed before data retrieved from web
	"""
	
	
	
	
						################							################
	################################			PROCESSING				################################
						################							################
	def __add_response_time(self,_time, index):
		self.timing_manager.add_response_time(_time, index)
		
	def __retrieve_response_from_next_queue_item(self,i,item,url):
		"""get content of next url in queue."""
		
		# don't re-use a user agent that didn't work before
		if self.errors[i]:
			ua_i = min(enumerate(self.ua_count), key = lambda p:p[1])[0]
		else:
			ua_i = i
		
		# mark that we are using user agent now
		self.__increment_ua_count(ua_i)
		
		# wait until we do not have a connection hold imposed
		wait(self.connection_wait_condition, self.__is_not_in_connection_wait)
		#with self.connection_wait_condition:
		#	self.connection_wait_condition.wait_for(
		#		self.__is_not_in_connection_wait
		#	)
		
		self.vprint(f'{current_thread().name} (i={i}): sending request',v=2)
		
		# start time for request is (roughly) now
		t = time.process_time()
		
		# send the request
		try:
			r = requests.get(
				self.format_url(url),
				headers = {'User-Agent':self.user_agents[ua_i]},
				timeout = self.timeout
				)
		except Exception as e:
			self.response_times[i] = time.process_time() - t
			self.__add_response_time(self.response_times[i], i)
			self.vprint('error encountered in request:',repr(e),v=2)
			raise
		else:
			self.response_times[i] = time.process_time() - t
			self.__add_response_time(self.response_times[i], i)
		
		#return the response
		return r
	
	def _process_content(self,index,url,response):
		#print('processing content: index',index)
		content = response.content.decode('utf-8')
		s = bs(content,features='lxml')
# 		if self.predict_bad_status(url,content):
# 			...
		processed = self.process_content(response)
		if self.in_memory: self.__store_in_memory(index,processed)
		else: self.save_result_to_disk(index,processed)
	
	def process_content(self,response):
		"""
		process url content after retrieved.
		
		default is to return utf-8 decoded content, doing nothing else with it
		"""
		return response
	
	
	
	
						################							################
	################################				MAIN				################################
						################							################
	
	def __try_resubmitting_to_queue(self,index,item,url):
		try:
			self.vprint(f'submitting index {index} back to queue', v=1)
			# if this has failed too many times, ThresholdExceededError is raised
			self.__increment_error(index)
			# otherwise, put back into queue to try again
			self.queue.put((index,item))
		except ThresholdExceededError:
			# too many failures for this particular item, mark it as failed and move on
			self.failed.append([index,url])
			self.__increment_processed()
		
	def scrape_loop(self):
		while self.__scrape_loop_inner():
			t=self.timing_manager.get_random_sleep_time()
			#print(f'{threading.currentThread().getName()}: sleeping for {t:.3f} seconds')
			time.sleep(t)
			
			pass # time.sleep call should be made inside loop, but currently is buggy there
	
	def __scrape_loop_inner(self):
		"""
		the loop that each thread repeats until all urls are processed
		returning False terminates the loop, returning True ensures it will run again
		
		NOT to be overridden.
		
		AN IDEA IS TO SUBCLASS THREAD AND PUT THIS IN THAT CLASS
		"""
		thread_name = current_thread().name
		
		if self.total_error >= self.total_err_threshold:
			self.print('\ntoo many 403 responses: exiting')
			return False
			
		try:
			# get item and its associated index, url, response object from queue
			index,item = self.queue.get_nowait()
			#if (index % self.thread_count == 0) and (index>=2*self.thread_count):
			#	self.sleep_adjuster_index = index
			#	self.__adjust_sleep_ready = True
			#	with self.sleep_interval_adjuster_condition:
			#		self.sleep_interval_adjuster_condition.notify()
			url = self.data_manager.extract_url_from_queue_item(item)
			
			"""
			#t=self.timing_manager.get_sleep_time(url)
			##print(f'{threading.currentThread().getName()}: sleeping for {t:.3f} seconds')
			#time.sleep(t)
			!	!	!
			on one occasion running this here with a chunked retriever,
			the last chunk did not save to disk; yet running on multiple occasions
			outside of '__scrape_loop_inner' had no troubles
			
			it also took much longer than it should have here,
			was much quicker outside of '__scrape_loop_inner',
			which doesn't make sense
			
			so something seems amiss
			"""
			
			response = self.__retrieve_response_from_next_queue_item(index,item,url)
			
			if self.test_conn_err:
				if index % self.CONN_ERR_TEST_INDEX == 0 and index>0:
					self.print(
						f'index = {index}={index}*{index//self.CONN_ERR_TEST_INDEX}; '
						'forcing ConnectionError test'
					)
					raise ConnectionError
				#print(f'got item at index {index} from queue')
			
			response.raise_for_status()
			# do something with it
			self._process_content(index, url, response)
			
			#mark successful
			self.success[index]=True
			
			#increment counter
			self.__increment_processed()
		
		except Empty:
			# queue is empty, we are done
			self.vprint(f'*** {thread_name} QUEUE IS OUT OF ITEMS ***', v=1)
			return False
		
		except HTTPError as e:
			#print(f'{current_thread().getName()}: {repr(e)}')
			if response.status_code==403:
				self.vprint(f'ERROR (code=403): index {index}', v=1)
				self.__try_resubmitting_to_queue(index,item,url)
			else:
				self.bad_status.append([index,url,response.status_code])
				self.__increment_processed()
				# too many bad statūs --> back off, don't want to raise a flag
				if len(self.bad_status) > self.__BAD_STATUS_THRESHOLD:
					self.running = False
					self.print('too many bad status responses: exiting')
					return False
		
		except ConnectionError:
			self.__on_connection_error()
			
			self.print(' a connection error was encountered at index {index}; a connection wait'
					   f' is enacted for {self.__CONN_ERR_WAIT} seconds')
			
			if not self.test_conn_err:
				
				self.__try_resubmitting_to_queue(index,item,url)
		
		except SSLError:
			self.print(f'ERROR (SSL): index {index}')
			self.__try_resubmitting_to_queue(index,item,url)
		
		except Exception as e: # do not let the thread experience an unhandled exception
			#raise
			found=False
			
			# see if this error was expected
			for (error_class, is_fatal, action) in self.expected_errors:
				if type(e) == error_class:
					found = True
					
					if action is not None:
						if callable(action):
							... # what signature should action have?
						else:
							...
					
					if is_fatal:
						self.__increment_processed()
					else: # try putting back in queue
						self.vprint(f'ERROR (accounted: {error_class}): index {index}', v=1)
						self.__try_resubmitting_to_queue(index,item,url)
					
					break
			
			if not found: # make a record for later analysis
				self.unaccounted_exceptions.append((index,url,repr(e)))
				self.__increment_processed()
			
			self.vprint(' * * * error encountered at index {index}: {repr(e)}',v=2)
		
		self.attempts[index] += 1
		self.on_attempt(index)
		# if we have gotten to here, the queue has not been exhausted
		#finally:
		#	#if (index>self.thread_count) and (index % self.thread_count == 0): 
		#	#	self.__adjust_sleep_window(index)
		#	
		#	# request has been attempted, successful or not, so increment attempt counter
		#	
		#	
		return True
	
	def on_attempt(self, index): pass
	
	def before_retrieve(self): pass
	
	def retrieve(self):
		for i,url in enumerate(self.url_items): self.queue.put((i,url))
		
		self.num_items_processed = 0
		self.running = True
		
		self.before_retrieve()
		
		self.start_time = time.time()
		for t in self.threads: t.start()
		
		self.printer.start()
		
		for t,n in zip(self.threads,self.thread_names):
			self.vprint('joining thread',n, v=2)
			t.join()
		
		self.running = False
		self.end_time = time.time()
		
		self.printer.join()
		
		self.__post_retrieve()
	
	def __post_retrieve(self):
		self.post_retrieve()
		self.process_in_memory_results()
		self.tally_results()
	
	def post_retrieve(self):
		pass
	
	def tally_results(self):
		self.print('total time elapsed:',self.end_time-self.start_time)
		#print(f'\nfinished; errors:<<<\n')
		#for i,v in enumerate(self.errors):
		#	if v: print(i, v)
		#print('>>>')
		print('\nfailed urls:')
		for index,url in self.failed: print(f'index={index} url=<{url}> ua=<{self.user_agents[index]}>')
		print('bad status:')
		for index,url,code in self.bad_status: print(f'index={index} code=<{code}> url=<{url}> ua=<{self.user_agents[index]}>')
		bad_status_indices=[i for i,u,c in self.bad_status]
		print('unaccounted exceptions:')
		for i,url,error in self.unaccounted_exceptions: print(f'<index={i}, url=<{url}>>:',error)
		
		self.failed_ua = np.array([
			self.user_agents[i] for i,v in enumerate(self.errors)
			if v and (i not in bad_status_indices)
		])
		self.success_ua = self.user_agents[np.where(self.success)[0]]
		
		print('failed ua:')
		print(self.failed_ua)
		#print('success ua:')
		#print(self.success_ua)
		print('exclusively failed ua:')
		print(set(self.failed_ua) - set(self.success_ua))
	
	def save_result_to_disk(self,index,processed):
		"""
		save a result of 'process_content' to disk.
		
		default is to do nothing
		"""
		pass
	
	def __store_in_memory(self,index,processed):
		"""
		store a result of 'process_content' to be processed when all urls are handled.
		
		NOT to be overridden.
		"""
		self.processed_results[index] = processed
		self.vprint(f'result at index {index} stored in self.processed_results', v=2)
	
	#def __process_in_memory_results(self):
	#	self.process_in_memory_results()
	
	def process_in_memory_results(self):
		"""
		
		
		default is to do nothing
		"""
		pass
	
	
	
	
	
						################							################
	################################				OTHER				################################
						################							################
	
	def get_unsuccesful_ua_isolators(self):
		"""
		Certain websites do not like certain user agents.
		using results from a run, this tries to isolate what
		user-agent components cause problems.
		"""
		#get unique components of user agents in each set
		#failed = set(ua.split(';').strip() for ua in self.failed_ua)
		#success = set(ua.split(';').strip() for ua in self.success)
		
		failed_component_groups = {cve_core.isolate_user_agent_components(ua) for ua in self.failed_ua}
		success_component_groups = {cve_core.isolate_user_agent_components(ua) for ua in self.success_ua}
		"""
		more work required; a component can be, for example:
			Mozilla/5.0 (Windows NT 6.1; Win64; x64)
			AppleWebKit/537.36 (KHTML, like Gecko)
			Chrome/60.0.3112.90
			Safari/537.36
			Mozilla/5.0 CK={} (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko
		
		The pattern is this:
		
		
		when I figure this out:
			create a unique component hierarchy listing: e.g.
				Mozilla
					Windows NT
					Win64
					x64
				AppleWebKit
					KHTML, like Gecko
				Safari
				Chrome
			
			compare components which are only in failed to those found (only?) in success
			using packaging.version.parse on version numbers,
				try to establish minimal version numbers required for success
		"""
		
		in_failed_and_not_in_success = failed - success
		
		failed_ua_types = ... #
	
	@wraps(Printer.print)
	def print(self,*a,**kw): self.printer.print(*a,**kw)
	
	@wraps(Printer.vprint)
	def vprint(self,*a,**kw): self.printer.vprint(*a,**kw)

associate_policy_with_cooperator(_ThreadDistributedResponseRetriever)

class HTMLTableRetriever(_ThreadDistributedResponseRetriever):
	"""
	class designed to scrape html tables from input urls
	"""
	def __init__(self,urls,in_memory=False):
		super().init(urls,in_memory=in_memory)
		if in_memory: self.tables=[None]*len(urls)
	
	def __get_tables(self,response): # is utf-8 okay in all situations?
		"""
		Get tables from a webpage; made simple by pandas.read_html.
		This function assumes that the 'url' argument has already been
		processed by 'format_url'.
		"""
		return pd.read_html(io.StringIO(response.content.decode('utf-8')))
	
	def process_tables(self,tables):
		"""
		Given the tables returned by a webpage,
		do something with them; default is to do nothing.
		"""
		return tables
	
	def process_content(self,response):
		return self.process_tables(self.__get_tables(response))
	
	#def store_in_memory


class ChunkedRetriever(_ThreadDistributedResponseRetriever):
	"""
	if we are scraping a large range of pages,
	we do not want to encounter a failure in the middle
	and have to start all over;
	
	so this class saves results to disk intermediately
	in a background thread
	
	To do:
		* currently result batches are saved on attempt, not on success;
		  handle case where something fails but later succeeds
		
		* when a block of results is successful, the results for that block
		  should be set to all None, or even better,
		  we should find a way (try the method __store_in_memory)
		  to delete that result entirely without messing up other results;
		  this would also require a __retrieve_from_memory method
		  to access those results, and in this case it would be best
		  to have a MemoryManager class to handle this
	"""
	
	__CHUNKSIZE = .01 # 1000
	__CHUNK_PATH = 'chunks/{id}/id={id}, chunk {chunk_index} i={start}-{end}.pickle'
	__CHUNK_PATH_2 = 'chunks/{folder}/{{id}}/chunk {{chunk_index}} i={{start}}-{{end}}.pickle'
	
	def set_disk_saver(self):
		self.disk_saver = DiskSaver(self.save_available_chunks, self.something_is_available_to_save, self.can_stop)
		self.disk_saver.set_printer(self.printer)
	
	def __init__(self, *a, chunksize=None, chunks=None, indices=None, path=None, **kw):
		super().__init__(*a, in_memory=True, **kw)
		
		self.print(f'initializing chunked retriever: size={self.size}')
		
		self.__set_indices(indices, chunksize, chunks)
		
		#self.save_on_retry_queue = Queue()
		self.save_on_retry_list = []
		
		if path is not None:
			self.__CHUNK_PATH = self.__CHUNK_PATH_2.format(folder=path)
		
# 		self.counter_lock = RLock()
# 		self.counter_condition = Condition(self.counter_lock)
		
		self.set_disk_saver()
		
	def __set_indices(self, indices, chunksize, chunks):
		"""
		Private method to set indices, chunksize.
		
		Set indices to denote chunk boudaries; the indices can be
		specified manually, or the chunksize will determine them
		programatically.
		
		If indices are specified manually, they will be sorted, and the
		index size(self)-1 will be added to the list if not already present.
		"""
		if indices is None:
			self.save_indices = None
			if chunksize: self.set_chunksize(chunksize)
			elif chunks: self.set_chunks(chunks)
		
		# these indices mark the end of individual chunks
			self.save_indices = [
				i for i in range(self.size)
				if (i+1 >= self.__CHUNKSIZE)
				and ((i+1) % self.__CHUNKSIZE == 0)
				]
			#self.save_indices.append(self.size - 1)
			#self.save_indices=sorted(self.save_indices)
		else:
			if any(i>self.size-1 for i in indices):
				raise ValueError(
					'indices specified must be <= size(self)-1: problem indices are '
					f'[i for i in indices if i>self.size-1)]'
				)
			self.save_indices=sorted(indices)
		
		self.vprint(f'self.save_indices preliminary: {self.save_indices}', v=1)
		
		if self.save_indices[-1] < self.size-1: self.save_indices.append(self.size-1)
		
		self.vprint(f'\t- initial self.save_indices sorted: {self.save_indices}', v=1)
		
		# every group of indices has a counter associated with it
		# the count tells how many urls from that group have been attempted
		self.save_indices_counts = {
			index: index-self.save_indices[i-1]
			for i,index in enumerate(self.save_indices)
		}
		
		self.save_indices_counts[self.save_indices[0]] = self.save_indices[0]+1
		self.save_indices_success_counts = copy.deepcopy(self.save_indices_counts)
		self.vprint(f'\t- initial self.save_indices_counts: {self.save_indices_counts}', v=1)
		
		self.save_indices_lower_bounds = {
			index: self.save_indices[i-1]+1
			for i,index in enumerate(self.save_indices)
		}
		
		self.save_indices_lower_bounds[self.save_indices[0]] = 0
		
		self.chunk_indices = \
			{index:i for i,index in enumerate(self.save_indices_lower_bounds.values())}
		
		self.vprint(f'\t- initial self.save_indices_lower_bounds: {self.save_indices_lower_bounds}', v=1)
	
	def set_chunksize(self,cs):
		"""
		Set approximate chunksize to be used when saving chunks.
		
		If set, at least n-1 out of n chunks will be this size.
		The last chunk will be smaller if size(self) % chunksize != 0.
		
		E.g. if chunksize is 11, size(self) = 105, the last chunk will
		have six elements, while all others will have 11 elements.
		
		::parameter:: cs:
			If a float,
				if 0 < cs < 1: chunksize = ceil(size(self) * cs)
				else: chunksize = ceil(cs)
			else if int: chunksize = cs
		"""
		if isinstance(cs, int):
			pass
		elif isinstance(cs, float):
			if cs<0:
				raise ValueError(f'chunksize cannot be negative: specified {cs}')
			if cs<1: cs = math.ceil(self.size*cs)
			else: cs = math.ceil(cs)
		else:
			raise ValueError(f'chunksize is of unrecognized type: {type(cs)}')
		
		if cs>=self.size:
			raise ValueError(f'chunksize is too large: {cs} >= self.size={self.size}')
		
		if cs<=1: self.__CHUNKSIZE=2
		else: self.__CHUNKSIZE = cs
	
	
	def set_chunks(self,c):
		self.set_chunksize(self.size // c)
	
	def find_nearest_save_index(self, index):
		return min(i for i in self.save_indices_lower_bounds if i >= index)
	
	def get_index_slice_start_end(self, index):
		start = self.save_indices_lower_bounds[index]
		end = index+1
		return start, end
	
	def save_chunk(self, index, start, end, full):
		"""save chunk to disk; default is to pickle, but this can be overridden."""
		
		path = self.__CHUNK_PATH.format(
			id = self.start_time,
			chunk_index = -1 if full else self.chunk_indices[start],
			start = start,
			end = f'{end} (full)' if full else end
		)
		
		with open(cve_core.makepath_from_file(path),'wb') as f:
			pickle.dump(self.get_processed_results()[start:end], f)
	
	def __save_chunk(self, index=None, full=False):
		if full:
			start, end = 0, self.size
		else:
			start, end = self.get_index_slice_start_end(index)
		
		self.vprint(f'saving chunk {start}:{end}', v=1)
		
		self.save_chunk(index, start, end, full)
	
	def save_available_chunks(self):
		keys = tuple(k for k,v in self.save_indices_counts.items() if not v)
		self.vprint(f'self.save_indices_counts: {self.save_indices_counts}', v=1)
		self.vprint(f'indices ready for saving: {keys}', v=1)
		for k in keys:
			self.__save_chunk(k)
			del self.save_indices_counts[k]
			self.save_indices.remove(k)
		
		for k in copy.copy(self.save_on_retry_list): #empty_queue(self.save_on_retry_queue)
			self.vprint(f'calling __save_chunk({k}) via self.save_on_retry_list', v=1)
			self.__save_chunk(k)
		
		self.save_on_retry_list=[]
	
	def retrieve_chunk(self,index):
		with open(f'id={self.start_time}, i={index}.pickle','rb') as f:
			obj = pickle.load(f)
		return obj
	
	#def check_saveable(self,index):
	#	return self.__check_availability_of_response_window(range(index))
	
	@wraps(_ThreadDistributedResponseRetriever._process_content)
	def on_attempt(self,index):
		self.attempt_notification(self.find_nearest_save_index(index),index)
		#if index in self.save_indices:
		#	self.disk_saver.put(index)
	
	def attempt_notification(self,save_index,index):
		self.vprint
		with self.disk_saver.save_condition:
			self.vprint(f'^^^ attempting notification on save_index {save_index} at index {index}', v=2)
			try:
				"""
				If we enter here, this is the first time this index
				has been passed to this method; why?
				
				Because an any attempt of a given index,
				successful or not, it passes through this function;
				
				And if an index is retried, it is retried only
				after all other indices have had their first attempt;
				
				Thus only when every index in a block is attempted
				once does the counter for that block become 0.
				
				So if the counter is not 0, it means that this"""
				self.save_indices_counts[save_index] -= 1
				if self.save_indices_counts[save_index] == 0:
					self.vprint(f'^^^       ready to save on save_index {save_index} at index {index}', v=2)
					self.disk_saver.notify()
			except KeyError:
				self.vprint(f'>>> index {index} has been attempted already', v=1)
				if self.success[index]:
					"""
					If we get here, this index has been attempted before,
					but did not succeed previously; it has now succeeded.
					
					Since it has now succeeded, save the result.
					"""
					self.vprint(f'>>> index {index} has succeeded, the associated chunk is being saved', v=1)
					#self.save_on_retry_queue.put(save_index)
					self.save_on_retry_list.append(save_index)
					self.disk_saver.notify()
	
	def something_is_available_to_save(self):
		self.vprint(f'something_is_available_to_save method:\n\tsave_on_retry_list: {self.save_on_retry_list}\n\tsave_indices_counts: {self.save_indices_counts}',v=1)
		
		available = (not all(self.save_indices_counts.values())) or bool(self.save_on_retry_list)
		can_stop = self.can_stop()
		
		return available and not can_stop
	
	def can_stop(self):
		self.vprint(f'can_stop method:\n\tsave_on_retry_list: {self.save_on_retry_list}\n\tsave_indices_counts: {self.save_indices_counts}',v=1)
		return not self.running
	
	def before_retrieve(self):
		self.disk_saver.start()
	
	def post_retrieve(self):
		if self.disk_saver.running():
			print('disk saver running; notifying')
			self.disk_saver.notify()
		self.disk_saver.join()
		self.__save_chunk(full=True)
		
		if self.size <= 1000:
			self.print(f'results post retrieval:\n{self.get_processed_results()}')
		else:
			self.print(f'results post retrieval: <size={self.size}>')
	
	def save_run(self):
		"""
		get all the files saved
		get the instructions for combining/processing these files
		save to disk as txt/pickle and/or other
		"""
		...
	
class DiskSaver:
	def __init__(self, save_method, check_method, stop_method):
		self.save_queue = Queue()
		self.save_thread = Thread(target = self.save_loop)
		self.__stop_value = None
		self.save_method = save_method
		self.check_method = check_method
		self.save_condition = Condition()
		self.stop_method = stop_method
		self.__printing=False
	
	def set_printer(self, printer):
		if isinstance(printer, Printer):
			self.printer=printer
			self.__printing = True
		else:
			raise TypeError(f"'printer' argument must be a <Printer>, received {type(printer)}")
	
	
	
	def save_loop(self):
		count=0
		while not self.stop_method():
			"""
			get all indices ready to be saved
			
			"""
			#value = self.save_queue.get()
			#if self.is_stop_value(value): break
			with self.save_condition:
				self.save_condition.wait()
				self.vprint(f'DiskSaver: iter {count} of save_loop while loop', v=1)
				if self.stop_method(): break
				#self.wait_for_check_method()
				self.vprint(f'DiskSaver: calling save_method', v=1)
				self.save_method()
				count+=1
	
	def wait_for_check_method(self, *a, **kw):
		self.vprint('DiskSaver: waiting for check method', v=1)
		wait(self.save_condition, self.check_method, *a, **kw)
	
	def stop(self): self.save_queue.put(self.__stop_value)
		
	def is_stop_value(self, value): return value is self.__stop_value
	
	def start(self):
		self.print('disk saver: starting')
		self.save_thread.start()
	
	def put(self, value): self.save_queue.put(value)
	
	def notify(self): notify(self.save_condition)
	
	def running(self): return self.save_thread.is_alive()
	
	def join(self):
		self.print('disk saver: joining')
		self.save_thread.join()
	
	
	@wraps(Printer.print)
	def print(self, *a, **kw):
		if self.printer is not None:
			self.printer.print(*a, **kw)
	
	@wraps(Printer.vprint)
	def vprint(self, *a, **kw):
		if self.printer is not None:
			self.printer.vprint(*a, **kw)


if __name__ == '__main__':
	#print('start of main')
	#c = TestCooperator(count_time=True, in_memory=True)
	
	t = _ThreadDistributedResponseRetriever(range(10))
	print('_ThreadDistributedResponseRetriever t policy dump:',t.policy.dump())