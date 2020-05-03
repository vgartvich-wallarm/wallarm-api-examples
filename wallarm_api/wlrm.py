#!/usr/bin/env python3
"""This script offers to work with Wallarm Cloud API"""

import asyncio
import json
import socket
from urllib.parse import urlparse
import requests
import aiohttp
import time

from elasticsearch import Elasticsearch
from .exceptions import NonSuccessResponse, ClosedSocket, NoSchemeDefined
from .helpers import _Decorators


class WallarmAPI:

    def __init__(self, uuid='', secret='', api='api.wallarm.com'):
        self.__uuid = uuid
        self.__secret = secret
        self.__api = api
        self.clientid = self.get_clientid()

    @_Decorators.try_decorator
    async def fetch(self, session, url, params=None, body=None, ssl=False):
        """Generic fetch method"""

        if params:
            async with session.get(url, params=params,
                                   headers={'X-WallarmAPI-UUID': self.__uuid,
                                            'X-WallarmAPI-Secret': self.__secret},
                                   ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                return await response.json()
        elif body:
            async with session.post(url, json=body,
                                    headers={'X-WallarmAPI-UUID': self.__uuid,
                                             'X-WallarmAPI-Secret': self.__secret},
                                    ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                return await response.json()

    def get_clientid(self):
        """The method to fetch a clientid for some queries"""

        url = f'https://{self.__api}/v1/objects/client'
        body = {"filter": {}}
        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                raise NonSuccessResponse(response.status_code, response.content)
        return response.json().get('body')[0].get('id')

    @_Decorators.try_decorator
    async def get_search(self, query='today'):
        """The method to fetch unix time by human-readable filter"""

        url = f'https://{self.__api}/v1/search'
        body = {"query": query, "time_zone": f'UTC{time.timezone/3600 if time.timezone/3600 != 0.0 else "+0"}'}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_attack_count(self, search_time):
        """The method to fetch the number of attacks by filter"""

        url = f'https://{self.__api}/v1/objects/attack/count'
        body = {"filter": {"!type": ["warn"], "time": search_time}}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_attack(self, search_time, poolid=None, limit=1000, offset=0):
        """The method to fetch attacks by filter"""

        url = f'https://{self.__api}/v1/objects/attack'
        body = {"filter": {"vulnid": None, "poolid": poolid, "!type": ["warn"],
                           "time": search_time},
                "limit": limit, "offset": offset, "order_by": "first_time", "order_desc": True}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_hit(self, attackid, limit=1000, offset=0):
        """The method to fetch hits by filter"""

        url = f'https://{self.__api}/v1/objects/hit'
        body = {"filter": [{"vulnid": None, "!type": ["warn", "marker"], "!experimental": True,
                            "attackid": [attackid], "!state": "falsepositive"}], "limit": limit, "offset": offset,
                "order_by": "time", "order_desc": True}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_rawhit(self, hitid):
        """The method to fetch details of hits by filter"""

        url = f'https://{self.__api}/v2/hit/details'
        params = {"id": hitid}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, params=params)
        return response

    @_Decorators.try_decorator
    async def get_vuln(self, limit=1000, offset=0):
        """The method to get vulnerabilities information"""

        url = f'https://{self.__api}/v1/objects/vuln'
        body = {"limit": limit, "offset": offset, "filter": {"status": "open"}, "order_by": "threat", "order_desc": True}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_action(self, hint_type=None, limit=1000, offset=0):
        """The method to get action information"""

        url = f'https://{self.__api}/v1/objects/action'
        if not hint_type:
            body = {"filter": {}, "limit": limit, "offset": offset}
        else:
            body = {"filter": {"hint_type": [hint_type]}, "limit": limit, "offset": offset}

        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_hint(self, limit=1000, offset=0):
        """The method to get hint information"""

        url = f'https://{self.__api}/v1/objects/hint'
        body = {"filter": {}, "order_by": "updated_at", "order_desc": True, "limit": limit, "offset": offset}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response

    @_Decorators.try_decorator
    async def get_blacklist(self, limit=1000):
        """The method to get blacklist information"""

        url = f'https://{self.__api}/v3/blacklist'
        params = {f"filter[clientid]": self.clientid, "limit": limit}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, params=params)
        return response

    @_Decorators.try_decorator
    async def get_blacklist_hist(self, search_time, limit=1000):
        """The method to get blacklist history"""

        start = search_time[0][0]
        end = search_time[0][1]

        url = f'https://{self.__api}/v3/blacklist/history'
        continuation = None
        full_resp = {}
        flag = True
        body = {"filter[clientid]": self.clientid, "filter[start_time]": start, "filter[end_time]": end,
                "limit": limit, "continuation": continuation}
        while True:
            with requests.get(url, params=body,
                              headers={'X-WallarmAPI-UUID': self.__uuid,
                                       'X-WallarmAPI-Secret': self.__secret}) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse(response.status, await response.text)
            continuation = response.json().get('body').get('continuation')

            if flag:
                full_resp = response.json()

            if continuation is not None:
                body['continuation'] = continuation
                if not flag:
                    full_resp['body']['objects'].extend(response.json().get('body').get('objects'))
            else:
                break
            flag = False
        return full_resp

    async def create_vpatch(self, instance=None, domain='example.com', action_name='.env'):
        """The method to create vpatch for an instance"""

        url = f'https://{self.__api}/v1/objects/hint/create'
        body = {"type": "vpatch", "action": [{"point": ["action_name"], "type": "iequal", "value": action_name},
                                             {"point": ["action_ext"], "type": "absent", "value": ""},
                                             {"point": ["header", "HOST"], "type": "iequal",
                                              "value": domain}],
                "clientid": self.clientid, "validated": True, "point": [["action_name"]], "attack_type": "any"}
        if instance:
            body['action'].append({"point": ["instance"], "type": "equal", "value": instance})

        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        return response


class SenderData:

    def __init__(self, address='http://localhost:9200', http_auth=None, collector_type=None):
        if collector_type == "es":
            if http_auth is not None:
                http_auth = (urlparse(f'http://{http_auth}@example.com').username,
                             urlparse(f'http://{http_auth}@example.com').password)
                self.es = Elasticsearch([address], http_auth=http_auth)
            else:
                self.es = Elasticsearch([address])
        self.address = address

    @_Decorators.try_decorator
    async def fetch(self, session, url, params=None, body=None, ssl=False, splunk_token=None, content_type=None):
        if not splunk_token:
            if params:
                async with session.get(url, params=params, ssl=ssl) as response:
                    if response.status not in [200, 201, 202, 204, 304]:
                        raise NonSuccessResponse(response.status, await response.json(content_type=None))
                    return await response.json()
            elif body:
                if content_type == 'text/plain':
                    async with session.post(url, data=json.dumps(body, indent=4), ssl=ssl, headers={'content-type': content_type}) as response:
                        if response.status not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse(response.status, await response.json(content_type=None))
                        return await response.json(content_type=None)
                else:
                    async with session.post(url, json=body, ssl=ssl) as response:
                        if response.status not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse(response.status, await response.json(content_type=None))
                        return await response.json(content_type=None)

        else:
            async with session.post(url, json=body,
                                    headers={'Authorization': f'Splunk {splunk_token}'},
                                    ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                return await response.json()

    @_Decorators.try_decorator
    async def tcp_client(self, host, port, message):
        reader, writer = await asyncio.open_connection(host, port)

        print(f'Send: {message!r}')
        writer.write((json.dumps(message)).encode())
        await writer.drain()

        print('Close the connection')
        writer.close()
        await writer.wait_closed()

    @_Decorators.try_decorator
    async def send_to_elastic(self, data, index='wallarm'):
        """This function sends data to ELK"""
        self.es.index(body=data, index=index)
        return print('Sent successfully')

    @_Decorators.try_decorator
    async def send_to_collector(self, data, tag=None, token=None, ssl=True, content_type=None):
        """This function sends data to HTTP/HTTPS/TCP/UDP Socket"""
        addr = urlparse(self.address)
        host = addr.hostname
        port = addr.port
        scheme = addr.scheme

        if scheme in ['http', 'https']:
            if tag:
                async with aiohttp.ClientSession() as session:
                    response = await self.fetch(session, f'{self.address}/{tag}', body=data, ssl=ssl)
                return response
            else:
                if token:
                    async with aiohttp.ClientSession() as session:
                        response = await self.fetch(session, f'{self.address}/services/collector/event/1.0',
                                                    body={'event': data}, ssl=ssl, splunk_token=token)
                    return response
                else:
                    if content_type:
                        async with aiohttp.ClientSession() as session:
                            response = await self.fetch(session, self.address, body=data, ssl=ssl, content_type='text/plain')
                        return response
                    else:
                        async with aiohttp.ClientSession() as session:
                            response = await self.fetch(session, self.address, body=data, ssl=ssl)
                        return response

        elif scheme == 'tcp':
            try:
                await self.tcp_client(host, port, data)
            except Exception:
                raise ClosedSocket('TCP socket is closed. Check whether it listens and available')
        elif scheme == 'udp':
            socket_data = f'{tag}: {data}'
            socket_data = json.dumps(socket_data).encode()
            while len(socket_data) > 0:
                # Blocking i/o because of weak guarantee of order
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((host, port))
                    s.send(socket_data[:500])
                socket_data = socket_data[500:]
        else:
            raise NoSchemeDefined("Specify one of the following schemes: http://, https://, tcp://, udp://")
        print('Sent successfully')
