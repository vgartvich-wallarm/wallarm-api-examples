# Wallarm-API-Fetcher

This is a PoC of asynchronous fetching data at several endpoints from Wallarm API

## Getting Started

* Download the project to local machine
* Add API credentials to the settings.py
* Use properly main.py to get information you need

### Prerequisites

* Python >=3.7

```sh
username@host:~$ pip3 install -r requirements.txt
```

### Usage

```sh 
./main.py
```

### What does the script do?

1. Make requests to the following endpoints
	* Attack
	* Hit
	* Action
	* Vulnerability
	* Blacklist
	* Blacklist history
	* Create a rule
2. Send JSON formatted data to http/tcp/upd collectors