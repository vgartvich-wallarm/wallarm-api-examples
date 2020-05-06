#!/usr/bin/env python3

import asyncio
import os
from wallarm_api.exceptions import EnvVariableNotSet
from wallarm_api.wlrm import WallarmAPI, SenderData


def get_env():
    UUID = os.environ.get('WALLARM_UUID')
    SECRET = os.environ.get('WALLARM_SECRET')
    API = os.environ.get('WALLARM_API', 'us1.api.wallarm.com')
    if None in [UUID, SECRET]:
        raise EnvVariableNotSet('Environment variables (UUID/SECRET) are not set')
    return UUID, SECRET, API


async def main():

    UUID, SECRET, API = get_env()

    api_call = WallarmAPI(uuid=UUID, secret=SECRET, api=API)
    search = await api_call.get_search(query='last hour')
    search_time = search['body']['attacks']['time']
    counter = asyncio.create_task(api_call.get_attack_count(search_time))
    attacks = asyncio.create_task(api_call.get_attack(search_time))
    # vulns = asyncio.create_task(api_call.get_vuln())
    # action = asyncio.create_task(api_call.get_action())
    # hint = asyncio.create_task(api_call.get_hint())
    # blacklist = asyncio.create_task(api_call.get_blacklist())
    # blacklist_hist = asyncio.create_task(api_call.get_blacklist_hist(search_time))
    # create_rule = asyncio.create_task(api_call.create_vpatch(instance='1', domain='wallarm.com', action_name='.git'))

    tasks = [counter, attacks]
    results = await asyncio.gather(*tasks)

    attacks_count = results[0]['body']['attacks']
    attack_ids = []
    for attack_body in results[1]['body']:
        attack_ids.append(attack_body['attackid'])
    number_of_attacks = len(attack_ids)
    while attacks_count > number_of_attacks:
        if attacks_count > number_of_attacks:
            results = await api_call.get_attack(search_time, offset=1000)
            for attack_body in results['body']:
                attack_ids.append(attack_body['attackid'])
            number_of_attacks += 1000
        else:
            break

    hit_coroutines = []
    for attack_id in attack_ids:
        hit_coroutines.append(asyncio.create_task(api_call.get_hit(attack_id)))
    hits = await asyncio.gather(*hit_coroutines)

    rawhit_coroutines = []
    for hit_body in hits:
        for hit_body_id in hit_body["body"]:
            hit_id = f'{hit_body_id["id"][0]}:{hit_body_id["id"][1]}'
            rawhit_coroutines.append(api_call.get_rawhit(hit_id))
    raw_hits = await asyncio.gather(*rawhit_coroutines)

    # elastic = SenderData(address='http://localhost:9200', http_auth='admin:password', collector_type='es')
    # [await elastic.send_to_elastic(body=rawhit, index='wallarm') for rawhit in raw_hits]

    # In case of Sumologic HTTP collector
    # sumo = SenderData(address='https://endpoint5.collection.us2.sumologic.com/receiver/v1/http/')
    # [await sumo.send_to_collector(rawhit) for rawhit in raw_hits]

    # In case of Splunk/Fluentd/HTTP collectors
    # splunk = SenderData(address='https://localhost:8088')
    # [await splunk.send_to_collector(rawhit, token='<token>', verify_ssl=False) for rawhit in raw_hits]

    # In case of tcp/syslog_tcp collectors
    # sys_tcp = SenderData(address='tcp://localhost:5140')
    # [await sys_tcp.send_to_collector(rawhit) for rawhit in raw_hits]

    # In case of udp/syslog
    # sys_udp = SenderData(address='udp://localhost:514')
    # [await sys_udp.send_to_collector(raw_hit) for raw_hit in raw_hits]

if __name__ == '__main__':
    asyncio.run(main())
