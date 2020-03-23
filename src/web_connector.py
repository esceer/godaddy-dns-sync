import requests

from src.config import Config, Logger
from src.utils import IpUtils


class GoDaddyConnector:
    def __init__(self, connection_params: Config, logger: Logger):
        self._connection_params = Config() if connection_params is None else connection_params
        self._logger = Logger() if logger is None else logger
        self._domain = 'esceer.com'
        self._dns_type = 'A'
        self._dns_record_name = '@'

    def fetch_ip_from_dns(self) -> str:
        self._logger.debug('Fetching current ip set in dns...')
        response = requests.get(self._get_url(), headers=self._get_headers())
        self._logger.debug(response.content)
        return IpUtils.gather_ip_from_dns_response(response.content.decode('utf-8'))

    def update_dns(self, target_ip: str) -> str:
        self._logger.debug('Updating dns information...')
        response = requests.put(self._get_url(), data=self._build_new_dns_info(target_ip), headers=self._get_headers())
        self._logger.debug(response.content)
        return response.content

    def _get_url(self) -> str:
        return '%s/v1/domains/%s/records/%s/%s' % (
            self._connection_params.get_godaddy_url_base(),
            self._domain,
            self._dns_type,
            self._dns_record_name
        )

    def _get_headers(self):
        return {
            'Authorization': 'sso-key %s:%s' % (
                self._connection_params.get_api_key(),
                self._connection_params.get_api_secret()
            ),
            'accept': 'application/json',
            'Content-Type': 'application/json'
        }

    def _build_new_dns_info(self, target_ip: str):
        return '[{ "data": "%s", "ttl": 3600 }]' % target_ip
