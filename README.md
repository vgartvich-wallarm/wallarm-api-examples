# Wallarm-API-Client

This is a package for asynchronous fetching data from Wallarm API

## Getting Started

* Download the project to local machine
* Add API credentials to the environment variables
`WALLARM_UUID` `WALLARM_SECRET` `WALLARM_API`
* Use main.py to get information you need

### Prerequisites

* Python >=3.7
* `requirements.txt`
```sh
$ pip3 install -r requirements.txt
```

### What does the script do?

1. Make requests to the endpoints

To get info about:
* Attacks
* Hits
* Actions
* Vulnerabilities
* Blacklist
* Blacklist history

To create a rule:
* Virtual Patch

2. Send JSON formatted data to the collectors:
* HTTP
* TCP
* UDP

### Usage example

To send raw requests to Splunk use generic function

```python3
splunk = SenderData(address='https://localhost:8088')
[await splunk.send_to_collector(rawhit, token='<token>', verify_ssl=False) for rawhit in raw_hits]
```

To get all vulnerabilities into results dictionary

```python3
vulns = asyncio.create_task(api_call.get_vuln())
results = await asyncio.gather(vulns)
```

To create a virtual patch to block access to the `example.com/.git` path

```python3
create_rule = asyncio.create_task(api_call.create_vpatch(instance='1', domain='example.com', action_name='.git'))
await asyncio.gather(*create_rule)
```
