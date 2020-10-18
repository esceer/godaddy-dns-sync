import re
import requests

from config import Config, Logger


class IpUtils:
    def __init__(self, config: Config, logger: Logger):
        self._config = Config() if config is None else config
        self._logger = Logger() if logger is None else logger

    def get_external_ip(self) -> str:
        external_ip = requests.get(self._config.get_ip_provider_url()).text
        self._logger.info('External ip address: %s' % external_ip)
        return external_ip

    @staticmethod
    def gather_ip_from_dns_response(dns_response_content: str) -> str:
        match = re.search(r'\"data\":\"(\d{1,4}\.\d{1,4}\.\d{1,4}\.\d{1,4})\"', dns_response_content)
        if match:
            return match.group(1)
        else:
            raise ValueError('Ip cannot be gathered from dns response: %s' % dns_response_content)