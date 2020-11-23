"""ProxyConfig module."""

import yaml

class ProxyConfig:
    """ProxyConfig class."""

    def __init__(self) -> None:
        """Construct a new ProxyConfig."""
        config_file = open("config.yaml")
        config = yaml.load(config_file, Loader=yaml.FullLoader)
        config_file.close()

        self.outbound = {
            'drop_all_traffic': False,
            'allowed_transport_protocols': None,
            'blocked_transport_protocols': None,
            'allowed_application_ports': None,
            'blocked_application_ports': None,
        }
        self.inbound = {
            'drop_all_traffic': False,
            'allowed_transport_protocols': None,
            'blocked_transport_protocols': None,
            'allowed_application_ports': None,
            'blocked_application_ports': None,
        }

        self.outbound.update(config.get('outbound'))
        self.inbound.update(config.get('inbound'))
