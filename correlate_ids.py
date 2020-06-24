#!/usr/bin/env python3

from datetime import datetime, timedelta
import sys
import json
import re
import pandas as pd

LOGFORMAT="/var/log/nsd/nsd-dnstap.log.%Y%m%d-%H"

def read_data(data):
    if isinstance(data, list) and not data:
        sys.stderr.write("No valid input supplied!\n")
        sys.exit(-1)

    ids = []
    for datum in data:
        datum['ts'] = datetime.utcfromtimestamp(datum['ts'])
        ids.append(datum['id'])

    if len(set(ids)) != len(ids):
        # this means that same probe was queried and failed!
        #sys.stderr.write("Double ID detected!\n")
        pass

    return (data, ids)
    
def read_dnstap_log(path, logls):
    try:
        with open(path, 'r') as f:
            for line in f:
                logls.append(json.loads(line))
    except FileNotFoundError:
        sys.stderr.write("Could not find {}\n".format(path))
    except json.decoder.JSONDecodeError:
        sys.stderr.write("Could not parse {}\n".format(path))
        

def parse_normal(query_pieces):
    probe_id = query_pieces[2]
    if not len(probe_id):
        probe_id = query_pieces[3]

    x = query_pieces[3].split('.')
    rslv_type = x[0]

    #if len(x) < 2:
    #    import IPython; IPython.embed()
    #    sys.exit(0)

    try:
        if 'x' not in x[1]:
            mtu = x[1]
        else:
            mtu = x[2]
    except IndexError:
        mtu = query_pieces[4].split('.')[1]

    return (probe_id, rslv_type, mtu)

def parse_2(query_pieces):
    probe_id = query_pieces[0]

    pieces = probe_id.split('.')
    if len(pieces) != 1:
        probe_id = pieces[1]

    return probe_id

def check_query(query, datum):
    prog = re.compile('[0-9]{4}')

    query = query.lower()
    query_pieces = query.split('-')
    if len(query_pieces) >= 4:
        probe_id, rslv_type, mtu = parse_normal(query_pieces)
    elif len(query_pieces) == 2:
        probe_id = parse_2(query_pieces)
        rslv_type = None
        mtu = None
    elif len(query_pieces) == 1:
        try:
            m = prog.search(query_pieces[0])
            probe_id = m.group()
        except AttributeError:
            probe_id = None
        rslv_type = None
        mtu = None
    else:
        sys.stderr.write("Unknown query found!\n")
        sys.stderr.write(query)
        #sys.exit(0)
        probe_id = None
        rslv_type = None
        mtu = None
        
    datum.append(probe_id)
    datum.append(rslv_type)
    datum.append(mtu)

def create_dataframe(logls):
    data = []

    for log in logls:
        datum = []

        # time
        datum.append(log['message']['query_time'])
        # address
        datum.append(log['message']['query_address'])
        # protocol
        datum.append(log['message']['socket_protocol'])

        #query
        qm = log['message']['query_message']
        try:
            query = qm.split('QUESTION SECTION:\n;')[1].split('\t')[0].lower()
        except IndexError:
            # no proper query supplied, invalid
            continue
        datum.append(query)

        # probe_id, type, mtu
        check_query(query,datum)

        # record
        try:
            datum.append(qm.split('IN\t ')[1].split('\n')[0])
        except IndexError:
            datum.append(None)

        # EDNS_buffer_size
        try:
            edns_udp = qm.split('udp: ')

            if len(edns_udp) == 1:
                # NO BUFFER SIZE
                raise IndexError

            buf_size = edns_udp[-1].split('\n')[0]
            buf_pieces = buf_size.split('id: ')

            if len(buf_pieces) > 1:
                buf_size = buf_pieces[1]

            datum.append(buf_size)
        except IndexError:
            # no EDNS(0)
            datum.append(None)

        datum.append(query.split('.')[0].lower())

        data.append(datum)

    return data

def load_stub_dnstap(results, rslv_type, ip_type):
    logls = []
    logpaths = []

    for result in results:
        logpaths.append(result['ts'].strftime(LOGFORMAT))

    logpaths = set(logpaths)

    for path in logpaths:
        read_dnstap_log(path, logls)

    data = create_dataframe(logls)
    # dont name any column query --> pandas error
    columns = ['time','address','protocol','dns_query','probe_id',
               'resolver_type','MTU','record','EDNS_buffer_size',
               'variable_section']
    df = pd.DataFrame(data, columns=columns)

    df = df[~df['dns_query'].str.contains('x')]

    df['time'] = pd.to_datetime(df['time'])
    df['probe_id'] = pd.to_numeric(df['probe_id'], errors='coerce')
    #df['MTU'] = df['MTU'].astype(int)

    ip = 'A' if ip_type == 4 else 'AAAA'

    df = df[df['resolver_type'] == rslv_type]
    df = df[df['record'] == ip]
    

    #import IPython; IPython.embed()

    return df

def datetime_range(begin, end, step=timedelta(hours=1)):
    span = end - begin
    dt = timedelta(0)
    while dt < span:
        yield begin + dt
        dt += step

# non Atlas relying log fetcher, duplicate :S
def load_rslv_dnstap(args, ip, resolver):
    logls = []
    logpaths = []

    for dt in datetime_range(datetime.fromisoformat(args.start),
							 datetime.fromisoformat(args.stop)):
        logpaths.append(dt.strftime(LOGFORMAT))
    
    logpaths = list(set(logpaths))
    for path in logpaths:
        read_dnstap_log(path, logls)

    data = create_dataframe(logls)
    # dont name any column query --> pandas error
    columns = ['time','address','protocol','dns_query','probe_id',
               'resolver_type','MTU','record','EDNS_buffer_size',
               'variable_section']
    df = pd.DataFrame(data, columns=columns)

    df['time'] = pd.to_datetime(df['time'])
    df['probe_id'] = pd.to_numeric(df['probe_id'], errors='coerce')

    ip = 'A' if ip == 4 else 'AAAA'

    df = df[df['resolver_type'] == resolver]
    df = df[df['record'] == ip]

    df['MTU'] = df['MTU'].astype(int)
    # remove outliers
    df = df.dropna()
    df['EDNS_buffer_size'] = df['EDNS_buffer_size'].astype(int)
    return df

