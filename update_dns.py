import configparser
import logging
import re
import requests
import sys


class Config:
    def __init__(self, environment: str):
        self._environment_mapping = {
            'dev': 'development',
            'prod': 'production'
        }
        self._config_dir = 'api/%s/godaddy.ini'
        self._config = self._parse_config_file(environment)

    def get_api_key(self) -> str:
        return self._config['Api']['api-key']

    def get_api_secret(self) -> str:
        return self._config['Api']['api-secret']

    def get_godaddy_url_base(self) -> str:
        return self._config['Url']['godaddy-url-base']

    def get_ip_provider_url(self) -> str:
        return self._config['Url']['ip-provider-url']

    def get_log_filepath(self) -> str:
        return self._config['Logging']['logdir'] + '/godaddy.log'

    def _parse_config_file(self, env) -> configparser.ConfigParser:
        if env in ['dev', 'prod']:
            config = configparser.ConfigParser()
            config.read(self._config_dir % self._environment_mapping.get(env))
            return config
        else:
            raise ValueError('Unknown environment: %s' % env)


class Logger:
    def __init__(self, config: Config):
        self._config = Config() if config is None else config
        handler = CloseFileHandler(config.get_log_filepath(), mode='a', encoding=None, delay=False)
        handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self._logger = logging.getLogger('godaddy')
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)

        # For debug only
        # self._setup_http_debug()

    def info(self, message) -> None:
        self._logger.info(message)

    def debug(self, message) -> None:
        self._logger.debug(message)

    def error(self, message) -> None:
        self._logger.error(message)

    def exception(self, message) -> None:
        self._logger.exception('Unexpected exception occurred: "%s"' % message)

    def _setup_http_debug(self) -> None:
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger('requests.packages.urllib3')
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True


class CloseFileHandler(logging.FileHandler):
    def emit(self, record) -> None:
        logging.FileHandler.emit(self, record)
        logging.FileHandler.close(self)


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
        return '[{ "data": "%s" }]' % target_ip


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


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('Invalid arguments')
        print('Usage:')
        print('update_dns.py <dev|prod>')
        sys.exit(1)

    environment = sys.argv[1]
    config = Config(environment)
    logger = Logger(config)

    ip_utils = IpUtils(config, logger)
    external_ip = ip_utils.get_external_ip()

    go_daddy_connector = GoDaddyConnector(config, logger)
    if external_ip != go_daddy_connector.fetch_ip_from_dns():
        go_daddy_connector.update_dns(external_ip)
