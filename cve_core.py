import re, os, inspect
from pathlib import Path
import numpy as np
import pandas as pd
from requests.exceptions import HTTPError
from requests_html import HTMLSession
import requests_html, requests
from bs4 import BeautifulSoup as bs

def makepath(p): #https://stackoverflow.com/questions/273192/
	"""
	make a directory path, creating intermediary directories as required
	:param p:
	:return:
	"""
	path=os.path.join(os.getcwd(),p)
	try: os.makedirs(path)
	except OSError:
		if not os.path.isdir(path): raise
	return path

def makepath_from_file(f):
	"""
	make a directory to host a file given the full file path
	:param f: full file path
	:return:
	"""
	makepath(f[:len(f)-f[::-1].index('/')])
	return f

def fopen(path,mode):
	return open(makepath_from_file(path),mode)

def print_update(*p):
	print('\x1b[2K\r',*p,flush=True,end='')

def shuffle_return(l):
	np.random.shuffle(l)
	return l

def format_exception(e):
	return ''.join(
		traceback.format_exception(
			etype=type(e),
			value=e,
			tb=e.__traceback__
		)
	)

class CVE_Error(Exception): pass

class ThresholdExceededError(CVE_Error):
	def __init__(self,threshold,message=None):
		self.threshold=threshold
		self.message=message
	
	def __str__(self):
		if self.message:
			return f'threshold exceeded: {self.threshold}; {self.message}'
		else:
			return f'threshold exceeded: {self.threshold}'

def add_dataset_description(name,desc):
	with open('data/datasets.file','a+') as f:
		f.write(f'{name}\t{desc}\n')


AKAMAI_FILTER_PDFS = re.compile('/state-of-the-internet-([a-z]+?)-reports-(\d+)')
AKAMAI_PDF_SPLIT = re.compile('\d')
def get_akamai_reports_from_url(url):
	session = HTMLSession()
	try:
		r=session.get(url)
		r.html.render()
		pdf_links = [
			l for l in r.html.absolute_links if l.endswith('.pdf')
			and 'summary' not in l
			and 'infographic' not in l
		]
		
		report_type,year = AKAMAI_FILTER_PDFS.search(url).groups()
		print(report_type,year)
		for l in pdf_links:
			name_components=l.split('/')[-1].split('-')
			name = tuple(c for c in name_components if AKAMAI_PDF_SPLIT.search(c))
			if len(name)<=1: name = ' '.join(c for c in name_components[2:])
			else: name = ' '.join(name)
			name = Path(name).with_suffix('.pdf')
			if name=='statement.pdf': pass
			print_update(report_type,year,'getting',name)
			r = session.get(l)
			#r.html.render()
			try:
				r.raise_for_status()
				with fopen(f'../sources/reports/akamai soti/{report_type}/{year}/{name}','wb') as f:
					f.write(r.content)
			except HTTPError:
				pass
		print_update(f'{report_type} {year} FINISHED\n')
	except Exception as e:
		print(f'\nERROR OCCURED: {repr(e)}\n')
	finally:
		session.close()

def get_akamai_reports(s=(2014,2020),c=(2008,2015)):
	schema = 'https://www.akamai.com/us/en/resources/our-thinking/state-of-the-internet-report/archives/state-of-the-internet-{type}-reports-{year}.jsp'
	if s:
		for year in range(*s):
			get_akamai_reports_from_url(schema.format(type='security',year=year))
	if c:
		for year in range(*c):
			get_akamai_reports_from_url(schema.format(type='connectivity',year=year))



def validate_parameter_types(**types):
	#@functools
	def validate_and_call_wrapper(func):
		spec = inspect.getfullargspec(func)
		if spec.kwonlydefaults: source=spec.kwonlydefaults
		else: source={p:v for p,v in zip(spec.args[-len(spec.defaults):],spec.defaults)}
		for parameter_name,required_parameter_type in types.items():
			assert isinstance(source[parameter_name],required_parameter_type), \
				"validate_parameter_types: the default value for parameter " \
				f"{parameter_name}={source[parameter_name]} " \
				f"in {func.__qualname__} is not of required type {required_parameter_type}" \
				"; check the function's definition"
		
		def validate_and_call(*args,**kwargs):
			print(f"calling 'validate_and_call' on {func.__qualname__} with args={args} and kw={kwargs}")
			for parameter_name,required_parameter_type in types.items():
				try:
					print(f'asserting isinstance({parameter_name}={kwargs[parameter_name]},{required_parameter_type})')
				except KeyError:
					pass
				else:
					assert kwargs[parameter_name]==required_parameter_type, \
					"validate_parameter_types: the value passed for parameter " \
					f"{parameter_name}={spec.kwonlydefaults[parameter_name]}" \
					f"in {func.__qualname__} is not of required type {required_parameter_type}"
			return func(*args,**kwargs)
		
		return validate_and_call
	
	return validate_and_call_wrapper

def isolate_user_agent_components(ua):
	return (m.group() for m in component_isolator.finditer(ua))

# regex pattern that isolates distinct components of a user agent
# a user agent can be anything, but looking at the most popular
# user agents, a pattern emerges:
#	a name + '?' + <version number> +
#	(optional) other text +
#	<';'-delimited names with version numbers between parentheses>
#	+(optional) a following qualifier, e.g. 'like Gecko'
component_isolator = re.compile(
	'.+?/(\d+\.)+\d+( ((?![(]).)*[(]((?![)]).)+[)]( like [^ ]+){,1}){,1}'
)
"""
explaining the pattern:
	<.+?/(\d+\.)+\d+>
		<.+?/>
		match 1+ characters until '/' is found
		
		<(\d+\.)+\d+>
		match (1+ <p1>) followed by <p2>
			p1: <\d+\.>
			match 1+ digits followed by a '.'
			
			p2: <\d+>
			match 1+ digits
		
	<( ((?![(]).)*[(]((?![)]).)+[)]( like [^ ]+){,1}){,1}>
	match <p1> 0 or 1 times
		
		p1: < ((?![(]).)*[(]((?![)]).)+[)]( like [^ ]+){,1}>
		match ' ' followed by <p1.1> followed by (<p1.2> 0 or 1 times)
			
			p1.1: ((?![(]).)*[(]((?![)]).)+[)]
			match (0+ of <p1.1.1>) followed by <p1.1.2>
				
				p1.1.1 ((?![(]).)*
				match 0+ characters that are not '('
				
				p1.1.2: <[(]((?![)]).)+[)]>
				match '(', then 1+ characters that are not ')', then ')'
			 
			p1.2: < like [^ ]+>
			match ' like ' followed by 1+ characters that are not ' '
"""
class UserAgent:
	def __init__(self, ua):
		self.components = {}
		for c in isolate_user_agent_components(ua):
			c=UserAgentFullComponent(c)
			self.components[c.name]=c

class UserAgentComponent:
	_fields={
		'full': ('name','version','extra','pieces','tail'),
		'piece': ('name','version')
	}
	
	def __init__(self,comptype,values):
		self.fields = self._fields[comptype]
		self.field_values = values

class UserAgentFullComponent(UserAgentComponent):
	def __init__(self,comp):
		super().__init__(
			'full',
			split_user_agent_component(comp)[:len(self.fields)]
		)
		
		if self.pieces: self.pieces = self.make_pieces(self.pieces)
	
	def __eq__(self,other):
		return not self.filter(other)
	
	def filter(self,other):
		"""
		return the differences between this component and 'other'
		"""
		# type equality ensures that both objects have equal 'fields' attributes
		if type(self)!=type(other):
			raise ValueError('cannot compare None')
		
		if self.name != other.name:
			raise ValueError('cannot compare user agents of different names:'
							 f' {self.name}, {other.name}')
		
		return tuple(self.get_difference(f,other) for f in self.fields[1:])
	
	def get_difference(self,field,other):
		if field=='pieces':
			return self.pieces.filter(other)
		else:
			s,o = self.getattr(field),other.getattr(field)
			if s==o: return None
			return s,o
	
	def make_pieces(self,pieces_string):
		return set(self.make_piece(p.strip()) for p in piecestr.split(';'))
	
	def make_piece(self,piecestr):
		try:
			i = len(p) - p[::-1].index(' ')
			name, version = p[:i-1], p[i:]
		except ValueError:
			name, version=p, '0.0'
		return UserAgentPieceComponent(name, version)
	
	def filter_pieces(self,other):
		s = {p.name:p.version for p in self.pieces}
		o = {p.name:p.version for p in other.pieces}
		
		self_names = set(s.keys())
		other_names = set(o.keys())
		
		keys_only_in_self = self_names - other_names
		keys_only_in_other = other_names - self_names
		
		keys_in_both = self_names & other_names
		
		diff={}
		
		for k,v in keys_in_both.items():
			if self < other: diff.add((self.name, self.version, other.version))
			if other < self: diff.add((other.name, other.version, self.version))
		
		return keys_only_in_self, keys_only_in_other, diff

class UserAgentPieceComponent(UserAgentComponent):
	"""
	if a user agent component has parentheses with fields inside,
	an instance of this class stores those fields
	"""
	#piece_identifier = 
	def __init__(self, name, version):
		super().__init__('piece', (name,version))
	
	#def __hash__(self)
	
	#def filter(self,other):
	#	.pieces
	
	def __lt__(self,other):
		return packaging.version(getattr(self,k)) < packaging.version(getattr(other,k))
	
	def __gt__(self,other):
		return packaging.version(getattr(self,k)) > packaging.version(getattr(other,k))
	
	def __eq__(self,other):
		return packaging.version(getattr(self,k)) == packaging.version(getattr(other,k))

comp_split_pattern = re.compile('([^/]+)/([^ ]+) *([^(]*)([(][^)]+[)]) {,1}(.*)')

def split_user_agent_component(comp):
	return comp_split_pattern.search(comp).groups()


class Struct:
	def __init__(self,**kw):
		for k,v in kw.items(): setattr(self,k,v)

def StructMaker(name, kw, mro=()):
	new = type(name, mro, {})
	new.__allowed_properties = {k:i for i,k in enumerate(kw)}
	
	for i,k in enumerate(kw):
		def f(self): return getattr(self, k)
		getname = f'get_{k}'
		f.__name__ = f.__qualname__ = getname
		setattr(new, getname, f)
		
		def f(self, obj):
			setattr(self, k, obj)
			print(f'set {k} to {obj}')
		setname = f'set_{k}'
		f.__name__ = f.__qualname__ = setname
		setattr(new, setname, f)
		
		print(f"getname='{getname}', setname='{setname}'")
	
	
	def init(self, **kwargs):
		for k,v in kwargs.items():
			if k not in self.__allowed_properties:
				raise ValueError(f'keyword {k} is not permitted for {type(self).__qualname__}')
			self.__prop = kwargs
			func = getattr(self,f'set_{k}')
			print(f'{func}: {v}')
			func(v)
	
	init.__name__ = '__init__'
	init.__qualname__ = f'{name}.__init__'
	new.__init__ = init
	
	return new




CVE_TABLE_PATH = 'tables/cve/{}.csv'
EDB_TABLE_PATH = 'tables/edb/{low}-{high}.file'

EXPLOIT_DB_URLS_FILE='exploit db urls.file'



if __name__=='__main__':
	#@validate_parameter_types(should_be_int=int,should_be_float=float)
	#def somefunc(a,b,should_be_int=2,should_be_float=5.0):
	#	print(a,b,should_be_int,should_be_float)
	#
	#somefunc(1,2,should_be_int=3,should_be_float=4.0)
	
	#Bundle=StructMaker('Bundle',{'a','b','c'})
	#b=Bundle(a=4,b=2,c=1)
	#print(f'a={b.get_a()}')
	#b.set_a(4)
	#print(b.get_a())
	
	get_akamai_reports( s=(2018,2020), c=None )