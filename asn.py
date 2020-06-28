import os
import pyasn
import pandas
import pickle
import json

asndb = pyasn.pyasn('asn46.dat')

pkls = [f for f in os.listdir('dfs') if os.path.isfile(os.path.join('dfs', f))]
pkls.sort()

i = 0
dfs = {}
for pkl in pkls:
    with open('./dfs/' + pkl, 'rb') as f:
        dfs[i] = pickle.load(f)
        i += 1

mtus = []
#import IPython; IPython.embed()
res = {}
for i in range(0,11):
	mtu = dfs[i]['MTU_y'].mode()[0]
	res[mtu] = dfs[i][~dfs[i]['address_x'].isin(dfs[10]['address_x'])]
	mtus.append(mtu)

#res1460 = dfs[2][~dfs[2]['address_x'].isin(dfs[10]['address_x'])]
#res1448 = dfs[3][~dfs[3]['address_x'].isin(dfs[10]['address_x'])]

asn = {}
for mtu in mtus:
	asn[mtu] = [asndb.lookup(addr)[0] for addr in res[mtu]['address_x']]

for mtu in mtus:
	with open(f'asns/asn{mtu}.json', 'w') as f:
		f.write(json.dumps(asn[mtu]))
