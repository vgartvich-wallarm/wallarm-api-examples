#!/usr/bin/env python3

import asyncio
import nest_asyncio
import os
from wallarm_api.exceptions import EnvVariableNotSet
from wallarm_api.wlrm import WallarmAPI, SenderData

# Global variable to access from function create_collector_object()
COLLECTOR_ADDRESS = ''


def get_env():
    UUID = os.environ.get('WALLARM_UUID')
    SECRET = os.environ.get('WALLARM_SECRET')
    API = os.environ.get('WALLARM_API', 'api.wallarm.com')
    COLLECTOR_ADDRESS = os.environ.get('COLLECTOR_ADDRESS')
    if None in [UUID, SECRET, COLLECTOR_ADDRESS]:
        raise EnvVariableNotSet('Environment variables (UUID/SECRET/COLLECTOR_ADDRESS) are not set')
    return UUID, SECRET, API, COLLECTOR_ADDRESS


def attack_callback(future):
    for attack_body in future.result()['body']:
        loggly = create_collector_object()
        asyncio.run(loggly.send_to_collector(attack_body))


def raw_hit_callback(future):
    loggly = create_collector_object()
    asyncio.run(loggly.send_to_collector(future.result()))


def create_collector_object():
    collector = SenderData(address=COLLECTOR_ADDRESS)
    return collector


async def main():
    UUID, SECRET, API, ADDRESS = get_env()
    global COLLECTOR_ADDRESS
    COLLECTOR_ADDRESS = ADDRESS

    poolid = int(os.environ.get("POOLID", 9))  # 9 - pool:"Demo Tiredful-API"
    api_call = WallarmAPI(uuid=UUID, secret=SECRET, api=API)
    search = await api_call.get_search(query='last hour')
    search_time = search['body']['attacks']['time']
    counter = asyncio.create_task(api_call.get_attack_count(search_time))
    attacks = asyncio.create_task(api_call.get_attack(search_time))
    attacks.add_done_callback(attack_callback)

    tasks = [counter, attacks]
    count_struct, attack_struct = await asyncio.gather(*tasks)

    attacks_count = count_struct['body']['attacks']
    attack_ids = []
    for attack_body in attack_struct['body']:
        attack_ids.append(attack_body['attackid'])
    number_of_attacks = len(attack_ids)
    offset = 1000
    while attacks_count > number_of_attacks:
        if attacks_count > number_of_attacks:
            attacks = asyncio.create_task(api_call.get_attack(search_time, offset=offset))
            attacks.add_done_callback(attack_callback)
            await attacks
            number_of_attacks += 1000
            offset += 1000
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
            raw_h = asyncio.create_task(api_call.get_rawhit(hit_id))
            raw_h.add_done_callback(raw_hit_callback)
            rawhit_coroutines.append(raw_h)
    await asyncio.gather(*rawhit_coroutines)


if __name__ == '__main__':
    # Patch asyncio to allow nested event loops
    nest_asyncio.apply()
    asyncio.run(main())
