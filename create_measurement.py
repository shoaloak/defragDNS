#!/usr/bin/env python3
# Create RIPE Atlas measurement
# https://atlas.ripe.net/docs/api/v2/reference/#!/measurements/Type_0

from datetime import datetime
from ripe.atlas.cousteau import (
  Dns,
  AtlasSource,
  AtlasCreateRequest,
)

ATLAS_API_KEY = "e6fe825b-1823-4024-b186-c789e568e94d"
QUERY_TEMPLATE='$r-$t-$p.{}.rootcanary.net'
PROBES=100

# https://atlas.ripe.net/docs/deprecated/measurement-creation-api/
dns = Dns(
    af=4,                               # IPv4 | IPv6
    description="IPv4 DNS 1500 MTU test",

    query_class='IN',                   # IN | CHAOS (TXT)
    query_type='A',                     # A | AAAA | ...
    query_argument=QUERY_TEMPLATE.format('1500-plus0.pmtu4'),

    use_macros=True,
    use_probe_resolver=True,
    resolve_on_probe=False,
    set_nsid_bit=False,
    protocol='UDP',
    udp_payload_size=4096,
    retry=0,
    spread=1,
    skip_dns_check=True,
    include_qbuf=True,
    include_abuf=True,
    prepend_probe_id=False,
    set_rd_bit=True,
    set_do_bit=False,
    set_cd_bit=False,
    timeout=5000,
)

# specify the probes, i.e. 5 worldwide
source = AtlasSource(type="area", value="WW", requested=PROBES)

atlas_request = AtlasCreateRequest(
    start_time=datetime.utcnow(),
    key=ATLAS_API_KEY,
    measurements=[dns],
    sources=[source],
    is_oneoff=True
)

(is_success, response) = atlas_request.create()
if is_success:
    print('Succesfully created the following measurements:')
    #todo json prettify...
    print(response)

#import IPython; IPython.embed()
