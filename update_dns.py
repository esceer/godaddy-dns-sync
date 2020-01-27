import configparser
import logging
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

    def get_api_key(self):
        return self._config['Api']['api-key']

    def get_api_secret(self):
        return self._config['Api']['api-secret']

    def get_godaddy_url_base(self):
        return self._config['Url']['godaddy-url-base']

    def get_ip_provider_url(self):
        return self._config['Url']['ip-provider-url']

    def get_log_filepath(self):
        return self._config['Logging']['logdir'] + '/godaddy.log'

    def _parse_config_file(self, env):
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
        self._setup_http_debug()

    def info(self, message):
        self._logger.info(message)

    def debug(self, message):
        self._logger.debug(message)

    def error(self, message):
        self._logger.error(message)

    def exception(self, message):
        self._logger.exception('Unexpected exception occurred: "%s"' % message)

    def _setup_http_debug(self):
        import http.client as http_client
        http_client.HTTPConnection.debuglevel = 1
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True


class CloseFileHandler(logging.FileHandler):
    def emit(self, record):
        logging.FileHandler.emit(self, record)
        logging.FileHandler.close(self)


class GoDaddyConnector:
    def __init__(self, connection_params: Config, logger: Logger):
        self._connection_params = Config() if connection_params is None else connection_params
        self._logger = Logger() if logger is None else logger
        self._domain = 'esceer.com'
        self._dns_type = 'A'
        self._dns_record_name = '@'

    def fetch_dns_info(self):
        self._logger.debug('Fetching current dns information...')
        response = requests.get(self._get_url(), headers=self._get_headers())
        self._logger.debug(response.content)
        return response.content

    def update_dns(self, target_ip: str):
        self._logger.debug('Updating dns information...')
        response = requests.put(self._get_url(), data=self._build_new_dns_info(target_ip), headers=self._get_headers())
        self._logger.debug(response.content)
        return response.content

    def _get_url(self):
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
        return [{
            'data': target_ip,
            'ttl': 3600
        }]


class IpUtils:
    def __init__(self, config: Config, logger: Logger):
        self._config = Config() if config is None else config
        self._logger = Logger() if logger is None else logger

    def get_external_ip(self):
        external_ip = requests.get(self._config.get_ip_provider_url()).text
        self._logger.info('External ip address: %s' % external_ip)
        return external_ip


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
    go_daddy_connector.fetch_dns_info()
    go_daddy_connector.update_dns(external_ip)
    go_daddy_connector.fetch_dns_info()
