import sys

from config import Config, Logger
from utils import IpUtils
from web_connector import GoDaddyConnector

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
