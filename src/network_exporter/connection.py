import logging
import threading
from datetime import datetime
from functools import wraps
from ipaddress import IPv4Address
from time import time

import netmiko
import panos
import panos.firewall
from cachetools import TTLCache, cached

logger = logging.getLogger("uvicorn.error")

CMD_OUT_CACHE = TTLCache(maxsize=100, ttl=360)


def timing(f):
    @wraps(f)
    def wrap(*args, **kw):
        ts = time()
        result = f(*args, **kw)
        te = time()
        logger.info("func:%r args:[%r, %r] took: %2.4f sec" % (f.__name__, args, kw, te - ts))
        return result

    return wrap


class CiscoConnection:
    """
    'Respawn' netmiko.ConnectHandler on OSError (i.e. when socket is closed.)
    """

    def __init__(self, username: str, password: str, device: IPv4Address):
        self._username = username
        self._host = device
        self._password = password
        self._device = {
            "device_type": "cisco_ios",
            "host": str(device),
            "password": password,
            "username": username,
            "timeout": 25,
        }
        self._connection = netmiko.ConnectHandler(**self._device)
        self._connection_established = datetime.now()
        self._lock = threading.Lock()

    def __repr__(self):
        return f"CiscoConnection({self._host}/{self._connection_established.strftime('%m_%d_%Y_%H_%M_%S')})"

    def _lock_acquire(self):
        logger.info("%s. acquiring netmiko lock.", self)
        self._lock.acquire()

    def _lock_release(self):
        logger.info("%s. releasing netmiko lock.", self)
        self._lock.release()

    @property
    @timing
    def connectHandler(self):
        # return self._connection
        try:
            self._connection.find_prompt()
        except OSError:
            logger.info("%s : socket was closed. re-opening.", self)
            self._connection.disconnect()
            self._connection = netmiko.ConnectHandler(**self._device)
            self._connection_established = datetime.now()

        return self._connection

    @timing
    def send_command(self, *args, **kwargs):
        if "use_textfsm" not in kwargs:
            kwargs["use_textfsm"] = True
        self._lock_acquire()
        output = self.connectHandler.send_command(*args, **kwargs)
        self._lock_release()
        return output

    @timing
    @cached(cache=CMD_OUT_CACHE, info=True)
    def send_command_cached(self, *args, **kwargs):
        return self.send_command(*args, **kwargs)

    @timing
    def find_prompt(self, *args, **kwargs):
        self._lock_acquire()
        output = self.connectHandler.find_prompt(*args, **kwargs)
        logger.info("%s. releasing netmiko lock.", self)
        self._lock_release()
        return output

    @property
    def established_time(self):
        return self._connection_established.timestamp()


class PanosConnection:
    """
    Python GC seems to suck, so we use a contextmanager to delete fw object at the end.
    """

    def __init__(self, hostname: str, username: str, password: str):
        self.hostname = hostname
        self.username = username
        self.password = password

    def __enter__(self):
        self.fw = panos.firewall.Firewall(
            hostname=self.hostname, api_username=self.username, api_password=self.password
        )
        return self.fw

    def __exit__(self, exc_type, exc_val, exc_tb):
        del self.fw
