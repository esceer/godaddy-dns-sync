import configparser
import logging


class Config:
    def __init__(self, environment: str):
        self._environment_mapping = {
            'dev': 'development',
            'prod': 'production'
        }
        self._config_dir = '../api/%s/godaddy.ini'
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
