#!/usr/bin/env python3

import asyncio
import os
from wallarm_api.exceptions import EnvVariableNotSet
from wallarm_api.wlrm import WallarmAPI, SenderData


def get_env():
    UUID = os.environ.get('WALLARM_UUID')
    SECRET = os.environ.get('WALLARM_SECRET')
    API = os.environ.get('WALLARM_API', 'api.wallarm.com')
    COLLECTOR_ADDRESS = os.environ.get('COLLECTOR_ADDRESS')
    if None in [UUID, SECRET, COLLECTOR_ADDRESS]:
        raise EnvVariableNotSet('Environment variables (UUID/SECRET/COLLECTOR_ADDRESS) are not set')
    return UUID, SECRET, API, COLLECTOR_ADDRESS


async def main():
    UUID, SECRET, API, COLLECTOR_ADDRESS = get_env()
    poolid = int(os.environ.get("POOLID", 9))  # 9 - pool:"Demo Tiredful-API"

    api_call = WallarmAPI(uuid=UUID, secret=SECRET, api=API)
    search = await api_call.get_search(query='last hour')
    search_time = search['body']['attacks']['time']
    counter = asyncio.create_task(api_call.get_attack_count(search_time))
    attacks = asyncio.create_task(api_call.get_attack(search_time, poolid=[poolid]))

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

    loggly = SenderData(address=COLLECTOR_ADDRESS)
    [await loggly.send_to_collector(rawhit) for rawhit in raw_hits]


if __name__ == '__main__':
    asyncio.run(main())
