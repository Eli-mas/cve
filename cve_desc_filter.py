"""
DoS								contains 'denial of service' OR 'dos'
Code Execution					contains 'code' AND 'execut'
Overflow						contains 'overflow'
Memory Corruption				...
Sql Injection					...
XSS								...
Directory Traversal				...
Http Response Splitting			...
Bypass something				...
Gain Information				...
Gain Privileges					...
CSRF							...
File Inclusion					...
"""

from math import ceil
import pandas as pd, numpy as np
from numpy import inf
import re, textwrap
from cve_process import *

def get_sub(table=None):
	if table is None: table = get_full_table()
	sub=table.loc[table.nv>1]
	return sub

case_columns = np.array([
	'affected by',
	'exists in',
	'resulting in',
	'lead to',
	'causes',
	'can cause',
	'could',
	'allow',
	'via'
])

def get_desc_types(table=None, sub=None):
	if table is None: table = get_full_table()
	if sub is None: sub = get_sub(table)
	sub = sub['desc']
	ss = sub.str
	cases = np.array([
		sub.apply(lambda s:			
			s[:s.find('. ')])								# AFFECTED BY
			.str.contains('affected by'),			
		
		sub.apply(lambda s: s[:s.find('. ')])			
			.apply(lambda s: bool(							# EXISTS IN
				re.search('exists* in',s)			
			)),			
		
		ss.contains('resulting in'),						# RESULTING IN
		
		sub.apply(lambda s: bool(
				re.search('leads* to', s)					# LEAD TO
			)),
		
		ss.contains('causes'),								# CAUSES
		
		ss.contains('can cause'),							# CAN CAUSE
		
		ss.contains('could'),								# COULD
		
		ss.contains('allow'),								# ALLOW
		
		ss.contains('via')									# VIA
	])
	n=sub[~np.any(cases,axis=0)]
	#n.sort_values().apply(lambda s: '\n'.join(textwrap.wrap(s,100))+'\n\n').to_csv("explore/desc_cases_filtering.file",sep='\t')
	#print(n.shape)
	
	desc_type_table = pd.DataFrame(
		cases.T, index=table.index[table.nv>1],
		columns=case_columns
	)
	
	desc_type_table['__COUNT'] = desc_type_table.sum(axis=1)
	desc_type_table['desc'] = sub
	desc_type_table[case_columns] = desc_type_table[case_columns].astype(bool)
	return desc_type_table

def get_desc_by_case(case, table=None, sub=None):
	if table is None: table = get_full_table()
	desc_type_table = get_desc_types(table,sub)
	indices_of_case = desc_type_table.index[desc_type_table[case]]
	return table.loc[indices_of_case].desc

def process_contained_words_as_callable(contained_words):
	if callable(contained_words):
		check = contained_words
	elif isinstance(contained_words,str):
		check = lambda d: contained_words in d
	else:
		check = lambda d: any(w in d for w in contained_words)
	return check

def check_description(table_where_count_gt_1, desc_type, contained_words):
	check = process_contained_words_as_callable(contained_words)
	# isolate rows of this type of vulnerability
	sub = table_where_count_gt_1.loc[table_where_count_gt_1[desc_type]]
	# count how many rows match the check
	condition = sub.desc.apply(check)
	count = condition.sum()
	total = sub.shape[0]
	# return	type,
	#			total # vulnerabilities of type,
	#			# of vulnerabilities of type matching check
	#			# of vulnerabilities of type NOT matching check
	#			% of vulnerabilities of type matching check
	#			% of vulnerabilities of type NOT matching check
	return sub, condition, desc_type, total, count, total-count, round(100*count/total,2), round(100*(total-count)/total,2)

vuln_types = {
	'dos': ('denial of service', ' dos'),
	'exec code': lambda d: 'execut' in d and ('code' in d or 'command' in d),
	'overflow': (' overflow', 'boundary checks', 'memory leak'),
	'mem. corr.': lambda d: 'memory' in d and 'corruption' in d and 'memory leak' not in d,
	'sql': lambda d: 'sql' in d and ('injection' in d or 'queries' in d or 'command' in d),
	'xss': ('xss','cross site script','cross-site script'),
	'dir. trav.': 'traversal',
	'http r.spl.': 'response splitting',
	'bypass': 'bypass',
	'+info': ('leak','sensitive','information'),
	'+priv': 'privilege',
	'csrf': ('request forgery', 'csrf'),
	'file inclusion': lambda d: 'file' in d and ('inclusion' in d or 'include' in d),
}
vuln_type_list = list(vuln_types.keys())

def rsplit(split_result):
	if len(split_result)==2: return split_result
	else: return ' '.join(split_result[:-1]),split_result[-1]

def get_primary_secondary(description, values):
	#print('get_primary_secondary: drow:',drow)
	
	AFFECTED_BY, EXISTS_IN, RESULTING_IN, LEAD_TO, CAUSES, CAN_CAUSE, COULD, ALLOW, VIA = \
		values
	#description = drow.desc
	if AFFECTED_BY:
		s = re.search('(?<= affected by).+?[.]',description)
		scan_for_primary = description[s.start():s.end()]
		s2=re.search('(?<=the attack vector is).+?[.]',description)
		if s2:
			scan_for_primary += description[s2.start():s2.end()]
			scan_for_secondary = description[s.end():s2.start()]+description[s2.end():]
		else:
			scan_for_secondary = description[s.end():]
	elif EXISTS_IN:
		scan_for_primary,scan_for_secondary = rsplit(re.split('exists* in', description))
	elif RESULTING_IN:
		scan_for_primary,scan_for_secondary = rsplit(description.split('resulting in'))
	elif LEAD_TO:
		scan_for_primary,scan_for_secondary = rsplit(re.split('leads* to', description))
	elif CAUSES:
		 scan_for_primary,scan_for_secondary = rsplit(description.split('causes'))
	elif CAN_CAUSE:
		 scan_for_primary,scan_for_secondary = rsplit(description.split('can cause'))
	elif COULD:
		scan_for_primary,scan_for_secondary = rsplit(description.split('could'))
	elif ALLOW:
		scan_for_primary,scan_for_secondary = rsplit(description.split('allow'))
	elif VIA:
		scan_for_secondary,scan_for_primary = rsplit(description.split('via'))
	
	if any((CAUSES,CAN_CAUSE,COULD,ALLOW)):
		if 'by' in scan_for_secondary:
			s1,s2 = rsplit(scan_for_secondary.split('by'))
			scan_for_primary += s2
			scan_for_secondary = s1
	
	return scan_for_primary, scan_for_secondary
	
def strfind(substring,superstring):
	i = superstring.find(substring)
	if i==-1: return inf
	return i

def findfirststr(substrings, superstring):
	finds = tuple(strfind(s,superstring) for s in substrings)
	if all(v is inf for v in finds): return None
	return min(enumerate(substrings), key = lambda p: finds[p[0]])[1]

def find_primary_vuln_type(description, dvalues, marked_vuln_types, expectation=None):
	if not any(dvalues): return None
	primary,secondary = get_primary_secondary(description, dvalues)
	#print('find_primary_vuln_type: primary:',primary)
	#print('find_primary_vuln_type: secondary',secondary)
	in_primary = set()
	in_secondary = set()
	for i,vtype in enumerate(marked_vuln_types):
		check = process_contained_words_as_callable(vuln_types[vtype])
		if check(primary): in_primary.add(vtype)
		if check(secondary): in_secondary.add(vtype)
	
	in_primary.difference_update(in_secondary)
	
	if not (in_primary or in_secondary): return None
	
	if len(in_primary)==1:
		primary,=in_primary
	
	elif len(in_primary)>1:
		primary = findfirststr(in_primary,primary)
	
	elif not in_primary:
		primary = findfirststr(in_secondary,secondary)
	
	if primary is None:
		primary = findfirststr(in_primary & in_secondary, description)
	
	if expectation is not None and primary != expectation:
		print(
			f'find_primary_vuln_type: expectation=<{expectation}>, primary=<{primary}>'
			f'description: {description}'
		)
	
	return primary
	
	"""
	if only 1 item in primary: we found the primary
	if no items in primary: assume primary is first vtype found in secondary
	"""

def find_primary_vuln_by_rows(desc_type_table_row, full_table_row, expectation=None):
	description = desc_type_table_row.desc
	#print('description:',description)
	marked_vuln_types = full_table_row[vuln_type_list][full_table_row[vuln_type_list]].index.values
	#print('marked_vuln_types:',marked_vuln_types)
	#print('desc_type_table_row')
	#print(desc_type_table_row)
	dvalues = desc_type_table_row[case_columns].values.astype(bool)
	primary = find_primary_vuln_type(description, dvalues, marked_vuln_types, expectation=expectation)
	if primary is None: secondary = marked_vuln_types
	else: secondary = tuple(vt for vt in marked_vuln_types if vt!=primary)## 
	return primary,secondary

def sql_analysis():
	table = get_full_table()
	sub = get_sub(table=table)
	desc_type_table = get_desc_types(table, sub)
	sql_multi_i = table.loc[(table.sql) & (table.nv>1)].index
	#print(sql_multi)
	sql_primaries = np.array([
		find_primary_vuln_by_rows(desc_type_table.loc[i], sub.loc[i])#,expectation='sql'
		for i in sql_multi_i#[:100]
	],dtype=object)
	#print(sql_primaries)
	#print(np.unique(sql_primaries[:,0].astype(str),return_counts=True))
	for i,(p,s) in zip(sql_multi_i,sql_primaries):
		table.loc[i,list(s)] = False
	
	return table

if __name__=='__main__':
	table = get_full_table()
	sub = get_sub(table=table)
	#desc_type_table = get_desc_types(table,sub)
	#desc_type_table.sort_values('__COUNT',ascending=False,inplace=True)
	#print(desc_type_table)
	#print(desc_type_table['allow'].sum())
	#
	#field_track = []
	#for i in range(counts_of_counts[4]):
	#	d=desc_type_table.iloc[i]
	#	fields = np.sort(d[columns].index[d[columns].astype(bool)].values)
	#	field_track.append(fields)
	#	print(f'{i} <{fields}>: {d.desc}\n')
	#field_track = np.array(field_track,dtype=object).astype(str)
	#print(np.unique(field_track,axis=0))
	
	#c = get_desc_by_case('allow',table=sub)
	#for d in c.iloc[:100]:
	#	print(d, end='\n\n')
	
	desc_type_table = get_desc_types(table, sub)
	counts_of_counts = desc_type_table['__COUNT'].groupby(desc_type_table['__COUNT']).count()
	print(counts_of_counts)
	"""
	for c in case_columns:
		print('  *  *'*4,'    '+c+'  ','  *  *'*4, sep='')
		indices = desc_type_table.index[desc_type_table[c] & desc_type_table['__COUNT']==1]
		desc_type_table_sub = desc_type_table.loc[indices]
		sub_table_sub = sub.loc[indices]
		for vt in vuln_type_list:
			print('\t\t*\t*\t',vt,'\t*\t*')
			intersect = sub_table_sub.loc[sub_table_sub[vt].astype(bool)]
			if len(intersect)==0: continue
			inds = intersect.index[::ceil(len(intersect)/4)]
			for idx in inds:
				#idx = inds[i]
				drow = desc_type_table.loc[idx]
				frow = table.loc[idx]
				print('drow.desc:',drow.desc)
				#print('drow')
				#print(drow)
				#print('frow')
				#print(frow)
				p,s = find_primary_vuln_by_rows(drow, frow)
				print(f'PRIMARY: <{p}>',f'SECONDARY: <{",".join(s)}>',end='\n\n')
	"""
	sql_multi_i = table.loc[(table.sql) & (table.nv>1)].index
	#print(sql_multi)
	sql_primaries = np.array([
		find_primary_vuln_by_rows(desc_type_table.loc[i], sub.loc[i],expectation='sql')
		for i in sql_multi_i#[:100]
	],dtype=object)
	#print(sql_primaries)
	print(np.unique(sql_primaries[:,0].astype(str),return_counts=True))
	
	#table = get_full_table()
	#table_where_count_gt_1 = table.loc[table.nv>1]
	#results = tuple(check_description(table_where_count_gt_1,v,w) for v,w in vuln_types.items())
	#
	#data = np.array([other for (subtable, condition, *other) in results],dtype=object)
	#print(data[np.argsort(-data[:,-2])])
	#for (subtable, condition, *other) in results:
	#	print(other)
	#	print(subtable[['CVE ID','desc']].loc[~condition],end='\n\n\n')