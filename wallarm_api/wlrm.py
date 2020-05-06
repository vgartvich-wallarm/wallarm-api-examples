#!/usr/bin/env python3
"""This script offers to work with Wallarm Cloud API"""
from __future__ import annotations

import asyncio
import json
import socket
from urllib.parse import urlparse
import requests
import aiohttp
import time
from threading import Lock, Thread
from typing import Optional

from elasticsearch import Elasticsearch
from .exceptions import NonSuccessResponse, ClosedSocket, NoSchemeDefined
from .helpers import _Decorators
from .log import logger


class SingletonMeta(type):
    """
    The Singleton class can be implemented in different ways in Python. Some
    possible methods include: base class, decorator, metaclass.
    """

    _instance: Optional[SenderData] = None
    _lock: Lock = Lock()

    def __call__(cls, *args, **kwargs):
        with cls._lock:
            if not cls._instance:
                cls._instance = super().__call__(*args, **kwargs)
        return cls._instance


class WallarmAPI:

    def __init__(self, uuid='', secret='', api='api.wallarm.com'):
        self.__uuid = uuid
        self.__secret = secret
        self.__api = api
        self.clientid = self.get_clientid()
        logger.info(f'Init has been successful and CLIENT ID: {self.clientid} has been taken from API')

    async def fetch(self, session, url, params=None, body=None, ssl=False):
        """Generic fetch method"""

        if params:
            async with session.get(url, params=params,
                                   headers={'X-WallarmAPI-UUID': self.__uuid,
                                            'X-WallarmAPI-Secret': self.__secret},
                                   ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    logger.critical(f"The {url} request with params {params} has failed due to the HTTP response code")
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                logger.debug(f"Everything is alright for the {url} request with params {params}")
                return await response.json()
        elif body:
            async with session.post(url, json=body,
                                    headers={'X-WallarmAPI-UUID': self.__uuid,
                                             'X-WallarmAPI-Secret': self.__secret},
                                    ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    logger.critical(f"The {url} request with body {body} has failed due to the HTTP response code")
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                logger.debug(f"Everything is alright for the {url} request with body {body}")
                return await response.json()

    def get_clientid(self):
        """The method to fetch a clientid for some queries"""

        url = f'https://{self.__api}/v1/objects/client'
        body = {"filter": {}}
        with requests.post(url, json=body,
                           headers={'X-WallarmAPI-UUID': self.__uuid,
                                    'X-WallarmAPI-Secret': self.__secret}) as response:
            if response.status_code not in [200, 201, 202, 204, 304]:
                logger.critical(
                    f'The response code to the https://{self.__api}/v1/objects/client was not successful. '
                    f'Check UUID/SECRET or the Internet connection')
                raise NonSuccessResponse(response.status_code, response.content)
        return response.json().get('body')[0].get('id')

    @_Decorators.try_decorator
    async def get_search(self, query='today'):
        """The method to fetch unix time by human-readable filter"""

        url = f'https://{self.__api}/v1/search'
        timezone_UTC = time.tzname[0]
        body = {"query": query, "time_zone": timezone_UTC}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_search has been successful by filter {body} '
                     f'It has taken unix search time from human-like string: "{query}" for {timezone_UTC}')
        logger.info(f'The requested search time has been received')
        return response

    @_Decorators.try_decorator
    async def get_attack_count(self, search_time, poolid=None):
        """The method to fetch the number of attacks by filter"""

        url = f'https://{self.__api}/v1/objects/attack/count'
        if poolid:
            body = {"filter": {"!type": ["warn"], "poolid": poolid, "time": search_time}}
        else:
            body = {"filter": {"!type": ["warn"], "time": search_time}}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_attack_count has been successful by filter {body}'
                     f'It has taken the number of attacks {response["body"]["attacks"]} by filter {body}')
        logger.info(f'The attack count has been received')
        return response

    @_Decorators.try_decorator
    async def get_attack(self, search_time, poolid=None, limit=1000, offset=0):
        """The method to fetch attacks by filter"""

        url = f'https://{self.__api}/v1/objects/attack'
        if poolid:
            body = {"filter": {"vulnid": None, "poolid": poolid, "!type": ["warn"],
                               "time": search_time},
                    "limit": limit, "offset": offset, "order_by": "first_time", "order_desc": True}
        else:
            body = {"filter": {"vulnid": None, "!type": ["warn"],
                               "time": search_time},
                    "limit": limit, "offset": offset, "order_by": "first_time", "order_desc": True}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_attack has been successful by filter {body}'
                     f' It has taken the attacks by filter')
        logger.info(f'The attacks (up to 1000) have been received')
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
        logger.debug(f'The function get_hit has been successful for an attack by filter {body}'
                     f'It has taken {len(response["body"])} hits  by filter')
        logger.info(f'The hits (up to 1000) for a specific attack have been received')
        return response

    @_Decorators.try_decorator
    async def get_rawhit(self, hitid):
        """The method to fetch details of hits by filter"""

        url = f'https://{self.__api}/v2/hit/details'
        params = {"id": hitid}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, params=params)
        logger.debug(f'The function get_rawhit has been successful for the hit {hitid} with params {params}'
                     f'It has taken the raw request for a hit')
        logger.info(f'The raw hit for hit ID has been received')
        return response

    @_Decorators.try_decorator
    async def get_vuln(self, limit=1000, offset=0):
        """The method to get vulnerabilities information"""

        url = f'https://{self.__api}/v1/objects/vuln'
        body = {"limit": limit, "offset": offset, "filter": {"status": "open"}, "order_by": "threat", "order_desc": True}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_vuln has been successful by filter {body}'
                     f'It has taken vulnerabilities')
        logger.info(f'The vulnerabilities (up to 1000) have been received')
        return response

    @_Decorators.try_decorator
    async def get_action(self, hint_type=None, limit=1000, offset=0):
        """The method to get action information"""

        url = f'https://{self.__api}/v1/objects/action'
        if hint_type:
            body = {"filter": {"hint_type": [hint_type]}, "limit": limit, "offset": offset}
        else:
            body = {"filter": {}, "limit": limit, "offset": offset}

        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_action has been successful by filter {body}'
                     f'It has taken actions for the rules')
        logger.info(f'The actions (up to 1000) have been received')
        return response

    @_Decorators.try_decorator
    async def get_hint(self, limit=1000, offset=0):
        """The method to get hint information"""

        url = f'https://{self.__api}/v1/objects/hint'
        body = {"filter": {}, "order_by": "updated_at", "order_desc": True, "limit": limit, "offset": offset}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, body=body)
        logger.debug(f'The function get_hint has been successful by filter {body}'
                     f'It has taken hints')
        logger.info(f'The hints (up to 1000) have been received')
        return response

    @_Decorators.try_decorator
    async def get_blacklist(self, limit=1000):
        """The method to get blacklist information"""

        url = f'https://{self.__api}/v3/blacklist'
        params = {f"filter[clientid]": self.clientid, "limit": limit}
        async with aiohttp.ClientSession() as session:
            response = await self.fetch(session, url, params=params)
        logger.debug(f'The function get_hint has been successful by filter {params}'
                     f'It has taken the current blacklist')
        logger.info(f'The blacklist (up to 1000) has been received')
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
        logger.debug(f'The function get_blacklist_hist has been successful by filter {body}'
                     f'It has taken the history of blacklist for the timeshift')
        logger.info(f'The blacklist history for the given period has been received')
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
        logger.debug(f'The function create_vpatch has been successful by filter {body}'
                     f'It has created a virtual patch')
        logger.info(f'The virtual patch has been created')
        return response


class SenderData(metaclass=SingletonMeta):

    def __init__(self, address='http://localhost:9200', http_auth=None, collector_type=None):
        if collector_type == "es":
            if http_auth is not None:
                http_auth = (urlparse(f'http://{http_auth}@example.com').username,
                             urlparse(f'http://{http_auth}@example.com').password)
                self.es = Elasticsearch([address], http_auth=http_auth)
            else:
                self.es = Elasticsearch([address])
        self.address = address
        logger.debug(f'Sender initialized successfully with the target address {self.address}')
        logger.info(f'The Sender object has been created')


    @_Decorators.try_decorator
    async def fetch(self, session, url, params=None, body=None, ssl=False, splunk_token=None, content_type=None):
        if splunk_token:
            async with session.post(url, json=body,
                                    headers={'Authorization': f'Splunk {splunk_token}'},
                                    ssl=ssl) as response:
                if response.status not in [200, 201, 202, 204, 304]:
                    raise NonSuccessResponse(response.status, await response.json(content_type=None))
                logger.debug(f"Everything is alright for the {url} request with body {body}. It directs to a Splunk collector")
                return await response.json()
        else:
            if params:
                async with session.get(url, params=params, ssl=ssl) as response:
                    if response.status not in [200, 201, 202, 204, 304]:
                        raise NonSuccessResponse(response.status, await response.json(content_type=None))
                    logger.debug(f"Everything is alright for the {url} request with params {params}")
                    return await response.json()
            elif body:
                if content_type == 'text/plain':
                    async with session.post(url, data=json.dumps(body, indent=4), ssl=ssl, headers={'content-type': content_type}) as response:
                        if response.status not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse(response.status, await response.json(content_type=None))
                        logger.debug(f"Everything is alright for the {url} request with body {body} as the text/plain")
                        return await response.json(content_type=None)
                else:
                    async with session.post(url, json=body, ssl=ssl) as response:
                        if response.status not in [200, 201, 202, 204, 304]:
                            raise NonSuccessResponse(response.status, await response.json(content_type=None))
                        logger.debug(f"Everything is alright for the {url} request with body {body}")
                        return await response.json(content_type=None)

    @_Decorators.try_decorator
    async def tcp_client(self, host, port, message):
        reader, writer = await asyncio.open_connection(host, port)

        logger.debug(f'Send: {message!r} to TCP collector')
        writer.write((json.dumps(message)).encode())
        await writer.drain()
        logger.debug('Close TCP the connection')
        writer.close()
        await writer.wait_closed()
        logger.debug(f"The function tcp_client has been successful. It sent data to TCP collector")
        logger.info(f'Sent via TCP socket')

    @_Decorators.try_decorator
    async def send_to_elastic(self, data, index='wallarm'):
        """This function sends data to ELK"""
        self.es.index(body=data, index=index)
        logger.debug(f"The function send_to_elastic has been successful."
                     f" It sent data to ELK directly with index {index}")
        logger.info(f'Sent to ELK')

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
                logger.info(f'Sent to a regular HTTP collector through scheme {scheme} with the tag {tag}')
                return response
            else:
                if token:
                    async with aiohttp.ClientSession() as session:
                        response = await self.fetch(session, f'{self.address}/services/collector/event/1.0',
                                                    body={'event': data}, ssl=ssl, splunk_token=token)
                    logger.info(f'Sent to the Splunk collector through {scheme}')
                    return response
                else:
                    if content_type:
                        async with aiohttp.ClientSession() as session:
                            response = await self.fetch(session, self.address, body=data, ssl=ssl, content_type='text/plain')
                        logger.info(f'Sent to a regular HTTP collector through scheme {scheme} with the content_type {content_type}')
                        return response
                    else:
                        async with aiohttp.ClientSession() as session:
                            response = await self.fetch(session, self.address, body=data, ssl=ssl)
                        logger.info(f'Sent to a regular HTTP collector through scheme {scheme} with the content_type application/json')
                        return response

        elif scheme == 'tcp':
            try:
                await self.tcp_client(host, port, data)
            except Exception:
                logger.error('TCP socket is closed. Check whether it listens and available')
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
            logger.info(f'Sent via UDP socket')
        else:
            raise NoSchemeDefined("Specify one of the following schemes: http://, https://, tcp://, udp://")
        logger.info(f"The function send_to_collector has been successful. It sent data to the defined collector")
