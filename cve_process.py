import os, re
import argparse
import numpy as np
import pandas as pd
from matplotlib import pyplot as plt

from cve_core import CVE_TABLE_PATH, print_update
FULL_TABLE_PATH = 'full_table.csv'
RESULTS_PATH = 'results/{}.file'

vulnerability_types = {
	'DoS':'DoS',
	'Code Execution':'Exec Code',
	'Overflow':'Overflow',
	'Memory Corruption':'Mem. Corr.',
	'Sql Injection':'Sql',
	'XSS':'XSS',
	'Directory Traversal':'Dir. Trav.',
	'Http Response Splitting':'Http R.Spl.',
	'Bypass something':'Bypass',
	'Gain Information':'+Info',
	'Gain Privileges':'+Priv',
	'CSRF':'CSRF',
	'File Inclusion':'File Inclusion'
}
#vulnerability_types = {k.lower():v.lower() for k,v in vulnerability_types.items()}
vulnerability_types = list(v.lower() for v in vulnerability_types.values())

ALLOW_SPLIT_PATTERN = re.compile('allows*.+?attackers*')

def split_by_allow(string,by_shortest=True):
	if by_shortest: key = lambda match: match.group.count(' ')
	else: key = lambda match: match.start()
	match = min(ALLOW_SPLIT_PATTERN.finditer(string), key=key)
	endpos = match.span()[-1]
	return string[:endpos].lower(),string[endpos:].lower()

def detect_vulnerability_type_in_description(description_string):
	...

def get_files():
	f = (f for f in os.listdir('tables/cve') if f.endswith('.csv'))
	return sorted(f, key = lambda p: int(p[:p.index('.')]))

def load_and_reindex(path):
	print_update(path)
	df = pd.read_csv(f'tables/cve/{path}',index_col=0)
	df.set_index('#',inplace=True)
	return df

def get_joined_table():
	files = get_files()
	return pd.concat([load_and_reindex(path) for path in files])

def get_full_table(load=True):
	#load=not ARGS.force
	if load and os.path.exists(FULL_TABLE_PATH):
		return pd.read_csv(FULL_TABLE_PATH,delimiter='\t',index_col=0)
	print_update('making table...\n')
	
	table = get_joined_table()
	
	for column,dtype in table.dtypes.iteritems():
		if dtype == object:
			table[column] = table[column].str.lower()
	
	table['Vulnerability Type(s)'].fillna('',inplace=True)
	table = table.loc[~table.desc.str.startswith('** disputed')]
	
	table[['pub_year','pub_month','pub_day']] = table['Publish Date'].str.split('-',expand=True).astype(int)
	table[['upd_year','upd_month','upd_day']] = table['Update Date'].str.split('-',expand=True).astype(int)
	
	table.drop(['Update Date','Publish Date'],axis=1,inplace=True)
	
	#table['CVE ID'] = table['CVE ID'].apply(lambda s: int(s.split('-')[-1]))
	
	for abbreviation in vulnerability_types:#.values()
		table[abbreviation] = table['Vulnerability Type(s)'].apply(lambda s: abbreviation in s)
	table['nv'] = table[vulnerability_types].sum(axis=1)#list().values()
	
	table.drop('Vulnerability Type(s)',inplace=True,axis=1)
	
	table.to_csv(FULL_TABLE_PATH,sep='\t')
	
	return table

def save_results(df,name):
	df.to_csv(RESULTS_PATH.format(name),sep='\t')

def get(name,*a,**kw):
	path = RESULTS_PATH.format(name)
	if not (ARGS.calc or ARGS.force) and os.path.exists(path):
		print('loading',name)
		return pd.read_csv(path,index_col=0,delimiter='\t')
	
	print('calculating',name)
	getter_functions[name](*a,**kw)
	return pd.read_csv(path,index_col=0,delimiter='\t')
	
def vulnerabilities_by_year():
	pub_year_grouping = table.groupby('pub_year')
	groupset = pub_year_grouping[vulnerability_types]#list().values()
	# total # of vulnerabilities for each type by year
	sums = groupset.sum().astype(int)
	# total # of vulnerabilities for each type by year
	proportions = sums.div(sums.sum(axis=1),axis=0)
	save_results(sums,'vulnerability counts by year')
	save_results(proportions,'vulnerability proportions by year')

def get_counts(vt,t):
	"""
	for a certain vulnerability type, get the fraction
	of cve entries of this type that have a certain value
	of the 'nv' column on the full table
	"""
	count_vt_grouping = t.groupby(['nv',vt]).nv.count().xs(True,level=vt)
	count_vt_grouping.name = vt
	#fractions_by_count = count_vt_grouping / count_vt_grouping.sum()
	return count_vt_grouping

def get_all_counts(t=None):
	if t is None: t=get_full_table()
	count_vals = np.unique(t.nv)
	count_vals = count_vals[count_vals>0]
	df = pd.DataFrame(np.zeros([count_vals.size,len(vulnerability_types)],dtype=int),
					  index=count_vals,
					  columns=vulnerability_types)
	for vt in vulnerability_types:
		df.update(get_counts(vt,t))
	
	return df.astype(int)

getter_functions={
	'vulnerability counts by year':vulnerabilities_by_year,
	'vulnerability proportions by year':vulnerabilities_by_year
}

if __name__=='__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-f','--force',action='store_true')
	parser.add_argument('-c','--calc',action='store_true')
	ARGS = parser.parse_args()
	
	table = get_full_table()
	sums = get('vulnerability counts by year')
	proportions = get('vulnerability proportions by year')
	#print(sums.values)
	#print(sums.sum(axis=1))
	#print(proportions)
	sums.plot(title='sums')
	plt.show()
	proportions.plot(title='proportions')
	plt.show()