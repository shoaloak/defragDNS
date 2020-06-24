#!/usr/bin/env python3

import sys
import json
from datetime import datetime
from ripe.atlas.cousteau import AtlasResultsRequest

def fetch_results(args):
    kwargs = {
        "msm_id": args.id,
        "start": datetime.fromisoformat(args.start),
        "stop": datetime.fromisoformat(args.stop),
    }
    return AtlasResultsRequest(**kwargs).create()

def get_json_formatted_failed_ids(args):
    is_success, results = fetch_results(args)

    if not is_success:
        raise ValueError(f"No data found for {args.id}")
        #sys.stderr.write("Unknown identifier!\n")
        #sys.exit(-1)

    if not len(results):
        sys.stderr.write("No results for that identifier.\n")
        #sys.exit(-1)

    #successes = [result for result in results if 'result' in result['resultset'][0]]

    ret = []
    for result in results:
        if 'error' in result:
            ret.append({'id': result['prb_id'],
                        'ts': result['timestamp']})

    return (len(results), ret)

def get_no_queries(args):
    is_success, results = fetch_results(args)

    if not is_success:
        raise ValueError(f"No data found for {args.id}")

    queries = 0
    for result in results:
        queries += len(result['resultset'])    

    return queries
