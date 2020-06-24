#!/usr/bin/env python3
import fetcher as fetch
import correlate_ids as corr
import json
import sys
import argparse

def stub_process(fetch_args, ip):
    #print(f"fetching Atlas from {fetch_args.start} till {fetch_args.stop}")
    try:
        no_queries, failed_json = fetch.get_json_formatted_failed_ids(fetch_args)
    except ValueError as err:
        print(err.args)
        return

    results, ids = corr.read_data(failed_json)

    #print("Loading dnstap logs...")
    log_df = corr.load_stub_dnstap(results, 'stub', ip);

    check = log_df['probe_id'].isin(ids)
    if True in check.unique():
        corr_df = log_df[check].copy(deep=True)

        final_df = corr_df[['probe_id','MTU', 'resolver_type', 'record',
                            'EDNS_buffer_size', 'dns_query']
                          ].sort_values(by=['MTU']).drop_duplicates()
        final_df['probe_id'] = final_df['probe_id'].astype(int)
        final_df = final_df.sort_values(by=['probe_id'])

        ret = final_df.shape[0]
    else:
        final_df = None
        ret = ''

    #total_queries = len(log_df)
    #total_queries = fetch.get_no_queries(fetch_args)
    total_queries = no_queries
    failed_queries = ret
    percent_failed = round((100 / total_queries) * failed_queries, 2)

    ret = [total_queries, failed_queries, percent_failed]

    try:
        return (ret, final_df['MTU'].mode()[0])
    except TypeError:
        sys.stderr.write("no results! maybe no logs of that date available?\n")
        sys.exit(-1)


def rslv_process(args, ip):
    #print("Loading dnstap logs...")
    dnstap_df = corr.load_rslv_dnstap(args, ip, "rslv")

    # clean up data
    dnstap_tcp_df = dnstap_df[dnstap_df['protocol'] == 'TCP'].reset_index()
    dnstap_tcp_df = dnstap_tcp_df[~dnstap_tcp_df['dns_query'].str.contains('x')]
    dnstap_tcp_df = dnstap_tcp_df.drop(columns='EDNS_buffer_size')
    dnstap_tcp_df = dnstap_tcp_df.drop_duplicates('dns_query')

    dnstap_udp_df = dnstap_df[dnstap_df['protocol'] == 'UDP'].reset_index()
    dnstap_udp_df = dnstap_udp_df[~dnstap_udp_df['dns_query'].str.contains('x')]
    dnstap_udp_df = dnstap_udp_df.drop_duplicates('dns_query')

    # correlate the initial UDP EDNS_message_size with the TCP query
    merged_df = dnstap_tcp_df.merge(dnstap_udp_df, on='variable_section', how='left')

    # check if the UDP MTU minus headers equals the EDNS
    if ip == 4:
        check_arr = ((merged_df['MTU_y'] - 28) > merged_df['EDNS_buffer_size'])
    elif ip == 6:
        check_arr = ((merged_df['MTU_y'] - 48) > merged_df['EDNS_buffer_size'])
    else:
        return

    results = merged_df[~check_arr]

    #total_queries = len(merged_df)
    total_queries = fetch.get_no_queries(args)
    failed_queries = len(results)
    percent_failed = round((100 / total_queries) * failed_queries, 2)

    return [total_queries, failed_queries, percent_failed]

    #ret = {"failed_queries": results.shape[0]}
    #print(ret)
    #import IPython; IPython.embed()
    #return results.shape[0]

def main(args):
    fetch_args = type("args", (object,), {})()
    bfmt = args.date + " {}:00:00"
    efmt = args.date + " {}:59:59"

    stub = {4:25741785,6:25741786}
    rslv = {4:25741787,6:25741788}

    for i in range(0, 24):
        fetch_args.start = bfmt.format(str(i).zfill(2))
        fetch_args.stop = efmt.format(str(i).zfill(2))
        output = {'datetime':fetch_args.start}

        fetch_args.id = stub[4]
        stub4_result, mtu = stub_process(fetch_args, 4)
        output['mtu'] = mtu
        output['total_queries_ipv4_stub'] = stub4_result[0]
        output['failed_queries_ipv4_stub'] = stub4_result[1]
        output['%failed_queries_ipv4_stub'] = stub4_result[2]

        fetch_args.id = stub[6]
        stub6_result, mtu = stub_process(fetch_args, 6)
        output['total_queries_ipv6_stub'] = stub6_result[0]
        output['failed_queries_ipv6_stub'] = stub6_result[1]
        output['%failed_queries_ipv6_stub'] = stub6_result[2]

        fetch_args.id = rslv[4]
        rslv4_result = rslv_process(fetch_args, 4)
        output['total_queries_ipv4_rslv'] = rslv4_result[0]
        output['failed_queries_ipv4_rslv'] = rslv4_result[1]
        output['%failed_queries_ipv4_rslv'] = rslv4_result[2]

        fetch_args.id = rslv[6]
        rslv6_result = rslv_process(fetch_args, 6)
        output['total_queries_ipv6_rslv'] = rslv6_result[0]
        output['failed_queries_ipv6_rslv'] = rslv6_result[1]
        output['%failed_queries_ipv6_rslv'] = rslv6_result[2]

        print(json.dumps(output))


if __name__ == '__main__':
    h = 'Use RIPE Atlas measurements and dnstap logs to log failed UDP DNS requests.'
    parser = argparse.ArgumentParser(description=h)
    parser.add_argument('-date', required=True,
                        help='The date (%Y-%m-%d) to analyze.')

    args = parser.parse_args()
    main(args)

