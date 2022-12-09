import json
import base64
import logging
import requests

from typing import Any, Callable, Optional, TypedDict, List

from certbot import interfaces
from certbot.plugins import common
from certbot import errors
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)


class Authenticator(dns_common.DNSAuthenticator):
    description = 'Obtain certificates using a DNS TXT record (if you are using Zone for DNS).'

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add: Callable[..., None],
                             default_propagation_seconds: int = 10) -> None:
        super().add_parser_arguments(add, default_propagation_seconds)
        add('credentials', help='Zone credentials INI file.')

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using the Zone API.'

    def _setup_credentials(self) -> None:
        self.credentials = self._configure_credentials(
            'credentials',
            'Zone credentials INI file',
            {
                'username': 'ZoneID username',
                'api_token': 'API token for Zone account'
            }
        )

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_zone_client().add_txt_record(domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        self._get_zone_client().del_txt_record(domain, validation_name, validation)

    def _get_zone_client(self) -> "_ZoneClient":
        if not self.credentials:
            raise errors.Error("Plugin has not been prepared.")
        return _ZoneClient(self.credentials.conf('username'), self.credentials.conf('api_token'))


class _ZoneDomain(TypedDict):
    name: str


class _ZoneRecord(TypedDict):
    id: str
    name: str
    destination: str


class _ZoneException(Exception):
    pass


class _ZoneClient:
    """
    Encapsulates all communication with the Zone API.
    """

    def __init__(self, username: str, api_token: str) -> None:
        token_bytes = (username + ":" + api_token).encode("ascii")
        self.headers = {
            "Authorization": "Basic " + base64.b64encode(token_bytes).decode("ascii"),
            "Content-Type": "application/json"
        }
        self.api_url = "https://api.zone.eu/v2"

    def _get(self, path: str):
        r = requests.get(self.api_url + path, headers=self.headers)

        if r.status_code != 200:
            raise _ZoneException(r.text)

        return r.json()

    def _post(self, path: str, data: Any):
        r = requests.post(self.api_url + path,
                          json.dumps(data), headers=self.headers)

        if r.status_code != 201:
            raise _ZoneException(r.text)

        return r.json()

    def _delete(self, path: str):
        r = requests.delete(self.api_url + path, headers=self.headers)

        if r.status_code != 204:
            raise _ZoneException(r.text)

    def add_txt_record(self, domain_name: str, record_name: str, destination: str) -> None:
        try:
            domain = self._find_domain(domain_name)
        except _ZoneException as e:
            logger.debug('Error finding domain using the Zone API: %s', e)
            raise errors.PluginError(
                'Error finding domain using the Zone API: %s'.format(e))

        try:
            result: List[_ZoneRecord] = self._post("/dns/" + domain['name'] + "/txt", {
                "name": record_name,
                "destination": destination
            })

            record_id = result[0]['id']
            logger.debug(
                'Successfully added TXT record with id: %s', record_id)
        except _ZoneException as e:
            logger.debug('Error adding TXT record using the Zone API: %s', e)
            raise errors.PluginError('Error adding TXT record using the Zone API: {0}'
                                     .format(e))

    def del_txt_record(self, domain_name: str, record_name: str, destination: str) -> None:
        try:
            domain = self._find_domain(domain_name)
        except _ZoneException as e:
            logger.debug('Error finding domain using the Zone API: %s', e)
            return

        try:
            domain_records = self.get_txt_records(domain)

            matching_records = [record for record in domain_records
                                if record['name'] == record_name
                                and record['destination'] == destination]
        except _ZoneException as e:
            logger.debug('Error getting DNS records using the Zone API: %s', e)
            return

        for record in matching_records:
            try:
                logger.debug('Removing TXT record with id: %s', record['id'])
                self._delete("/dns/" + domain['name'] + "/txt/" + record['id'])
            except _ZoneException as e:
                logger.warning(
                    'Error deleting TXT record %s using the Zone API: %s', record['id'], e)

    def get_txt_records(self, domain: _ZoneDomain) -> List[_ZoneRecord]:
        return self._get("/dns/" + domain['name'] + "/txt")

    def get_all_domains(self) -> List[_ZoneDomain]:
        return self._get("/domain")

    def _find_domain(self, domain_name: str) -> _ZoneDomain:
        domain_name_guesses = dns_common.base_domain_name_guesses(domain_name)
        domains = self.get_all_domains()

        for guess in domain_name_guesses:
            matches = [domain for domain in domains if domain['name'] == guess]

            if matches:
                domain = matches[0]
                logger.debug(
                    'Found base domain for %s using name %s', domain_name, guess)
                return domain

        raise errors.PluginError(f'Unable to determine base domain for {domain_name} using names: '
                                 f'{domain_name_guesses}.')
