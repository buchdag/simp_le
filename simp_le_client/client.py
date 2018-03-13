#!/usr/bin/env python
#
# Simple Let's Encrypt client.
#
# Copyright (C) 2015  Jakub Warmuz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
"""Simple Let's Encrypt client."""
import collections
import datetime
import errno
import os
import re

import pkg_resources

import six
from six.moves import zip  # pylint: disable=redefined-builtin

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

import josepy as jose
import pytz

from acme import client as acme_client
from acme import crypto_util
from acme import challenges
from acme import errors as acme_errors
from acme import messages

from simp_le_client.log import logger
from simp_le_client import storage
from simp_le_client import utils

# pylint: disable=too-many-lines


VERSION = pkg_resources.require('simp_le-client')[0].version
URL = 'https://github.com/zenhack/simp_le'

LE_PRODUCTION_URI = 'https://acme-v01.api.letsencrypt.org/directory'
# https://letsencrypt.org/2015/11/09/why-90-days.html
LE_CERT_VALIDITY = 90 * 24 * 60 * 60
DEFAULT_VALID_MIN = LE_CERT_VALIDITY / 3

EXIT_RENEWAL = EXIT_TESTS_OK = EXIT_REVOKE_OK = EXIT_HELP_VERSION_OK = 0
EXIT_NO_RENEWAL = 1
EXIT_ERROR = 2


class Error(Exception):
    """simp_le error."""


class Vhost(collections.namedtuple('Vhost', 'name root')):
    """Vhost: domain name and public html root."""
    _SEP = ':'

    @classmethod
    def decode(cls, data):
        # pylint: disable=anomalous-unicode-escape-in-string
        """Decode vhost and perform basic sanitization on the domain name:
        - raise an error if domain is not ASCII (Internationalized Domain
        Names are supported by Let's Encrypt using punycode).
        - converts domain to lowercase.

        >>> Vhost.decode('example.com')
        Vhost(name='example.com', root=None)
        >>> Vhost.decode('EXAMPLE.COM')
        Vhost(name='example.com', root=None)

        utf-8 test with example.china:
        >>> Vhost.decode(u'\u4f8b\u5982.\u4e2d\u56fd')
        Traceback (most recent call last):
        ...
        Error: Non-ASCII domain names aren't supported. To issue
        for an Internationalized Domain Name, use Punycode.
        >>> Vhost.decode('example.com:/var/www/html')
        Vhost(name='example.com', root='/var/www/html')
        >>> Vhost.decode(Vhost(name='example.com', root=None))
        Vhost(name='example.com', root=None)
        """
        if isinstance(data, cls):
            return data
        parts = data.split(cls._SEP, 1)

        try:
            utf8test = parts[0]
            if isinstance(utf8test, six.binary_type):
                utf8test = utf8test.decode('utf-8')
            utf8test.encode('ascii')
        except UnicodeError:
            raise Error("Non-ASCII domain names aren't supported. "
                        "To issue for an Internationalized Domain Name, "
                        "use Punycode.")

        parts[0] = parts[0].lower()

        parts.append(None)
        return cls(name=parts[0], root=parts[1])


def supported_challb(authorization):
    """Find supported challenge body.

    This plugin supports only `http-01`, so CA must offer it as a
    single-element combo. If this is not the case this function returns
    `None`.

    Returns:
      `acme.messages.ChallengeBody` with `http-01` challenge or `None`.
    """
    for combo in authorization.body.combinations:
        first_challb = authorization.body.challenges[combo[0]]
        if len(combo) == 1 and isinstance(
                first_challb.chall, challenges.HTTP01):
            return first_challb
    return None


def compute_roots(vhosts, default_root):
    """Compute webroots.

    Args:
      vhosts: collection of `Vhost` objects.
      default_root: Default webroot path.

    Returns:
      Dictionary mapping vhost name to its webroot path. Vhosts without
      a root will be pre-populated with the `default_root`.
    """
    roots = {}
    for vhost in vhosts:
        if vhost.root is not None:
            root = vhost.root

            # We've had users mistakenly try to supplie a port number, like
            # example.com:8000 (see issue #51). Theoretically, this could be
            # a valid path, but it's *probably* a mistake; warn the user:
            match = re.match(r'^([0-9]{1,5})(:|$)', root)
            if match:
                portno, _ = match.groups()
                if 0 <= int(portno) < 2 ** 16:
                    logger.warning("Your webroot path (%s) looks like it is "
                                   "a port number or starts with one; this "
                                   "should be a directory name/path. "
                                   "Continuing anyway, but this may not be "
                                   "what you intended...", root)
        else:
            root = default_root
        roots[vhost.name] = root

    empty_roots = dict((name, root)
                       for name, root in six.iteritems(roots) if root is None)
    if empty_roots:
        raise Error('Root for the following host(s) were not specified: {0}. '
                    'Try --default_root or use -d example.com:/var/www/html '
                    'syntax'.format(', '.join(empty_roots)))
    return roots


def save_validation(root, challb, validation):
    """Save validation to webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
      validation: `http-01` validation
    """
    try:
        os.makedirs(os.path.join(root, challb.URI_ROOT_PATH))
    except OSError as error:
        if error.errno != errno.EEXIST:
            # directory doesn't already exist and we cannot create it
            raise
    path = os.path.join(root, challb.path[1:])
    with open(path, 'w') as validation_file:
        logger.debug('Saving validation (%r) at %s', validation, path)
        validation_file.write(validation)


def remove_validation(root, challb):
    """Remove validation from webroot.

    Args:
      root: Webroot path.
      challb: `acme.messages.ChallengeBody` with `http-01` challenge.
    """
    path = os.path.join(root, challb.path[1:])
    try:
        logger.debug('Removing validation file at %s', path)
        os.remove(path)
    except OSError as error:
        logger.error('Could not remove validation '
                     'file at %s : %s', path, error)


def persist_data(args, existing_data, new_data):
    """Persist data on disk.

    Uses all selected plugins to save certificate data to disk.
    """
    for plugin_name in args.ioplugins:
        plugin = storage.IOPlugin.registered[plugin_name]
        if any(persisted and existing != new
               for persisted, existing, new in
               zip(plugin.persisted(), existing_data, new_data)):
            plugin.save(new_data)


def renewal_necessary(cert, valid_min):
    """Is renewal necessary?

    >>> cert = crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60))
    >>> renewal_necessary(cert, 60 * 60 * 24)
    True
    >>> renewal_necessary(cert, 1)
    False
    """
    now = pytz.utc.localize(datetime.datetime.utcnow())
    expiry = utils.asn1_generalizedtime_to_dt(cert.get_notAfter().decode())
    diff = expiry - now
    logger.debug('Certificate expires in %s on %s (relative to %s)',
                 diff, expiry, now)
    return diff < datetime.timedelta(seconds=valid_min)


def check_plugins_persist_all(ioplugins):
    """Do plugins cover all components (key/cert/chain)?"""
    persisted = storage.IOPlugin.Data(
        account_key=False, key=False, cert=False, chain=False)
    for plugin_name in ioplugins:
        persisted = storage.IOPlugin.Data(*utils.componentwise_or(
            persisted, storage.IOPlugin.registered[plugin_name].persisted()))

    not_persisted = set([
        component
        for component, persist in six.iteritems(persisted._asdict())
        if not persist])
    if not_persisted:
        raise Error('Selected IO plugins do not cover the following '
                    'components: {0}.'.format(', '.join(not_persisted)))


def load_existing_data(ioplugins):
    """Load existing data from disk.

    Returns:
      `storage.IOPlugin.Data` with all plugin data merged and sanity checked
      for coherence.
    """
    def merge(first, second, field):
        """Merge data from two plugins.

        >>> add(None, 1, 'foo')
        1
        >>> add(1, None, 'foo')
        1
        >>> add(None, None, 'foo')
        None
        >>> add(1, 2, 'foo')
        Error: Some plugins returned conflicting data for the "foo" component
        """
        if first is not None and second is not None and first != second:
            raise Error('Some plugins returned conflicting data for '
                        'the "{0}" component'.format(field))
        return first or second

    all_existing = storage.IOPlugin.EMPTY_DATA
    for plugin_name in ioplugins:
        all_persisted = storage.IOPlugin.registered[plugin_name].persisted()
        all_data = storage.IOPlugin.registered[plugin_name].load()

        # Check that plugins obey the interface: "`not persisted`
        # implies `data is None`" which is equivalent to `persisted or
        # data is None`
        assert all(persisted or data is None
                   for persisted, data in zip(all_persisted, all_data))

        all_existing = storage.IOPlugin.Data(*(merge(*data) for data in zip(
            all_existing, all_data, all_data._fields)))
    return all_existing


def pyopenssl_cert_or_req_san(cert):
    """SANs from cert or csr."""
    # This function is not inlined mainly because pylint is bugged
    # when it comes to locally disabling protected access...
    # pylint: disable=protected-access
    return crypto_util._pyopenssl_cert_or_req_san(cert)


def valid_existing_cert(cert, vhosts, valid_min):
    """Is the existing cert data valid for enough time?

    If provided certificate is `None`, then always return True:

    >>> valid_existing_cert(cert=None, vhosts=[], valid_min=0)
    False

    >>> cert = jose.ComparableX509(crypto_util.gen_ss_cert(
    ...     gen_pkey(1024), ['example.com'], validity=(60 *60)))

    Return True iff `valid_min` is not bigger than certificate lifespan:

    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 0)
    True
    >>> valid_existing_cert(cert, [Vhost.decode('example.com')], 60 * 60 + 1)
    False

    If SANs mismatch return False no matter if expiring or not:

    >>> valid_existing_cert(cert, [Vhost.decode('example.net')], 0)
    False
    >>> valid_existing_cert(cert, [Vhost.decode('example.org')], 60 * 60 + 1)
    False
    """
    if cert is None:
        return False  # no existing certificate

    # renew existing?
    new_sans = [vhost.name for vhost in vhosts]
    existing_sans = pyopenssl_cert_or_req_san(cert.wrapped)
    logger.debug('Existing SANs: %r, new: %r', existing_sans, new_sans)
    return (set(existing_sans) == set(new_sans)
            and not renewal_necessary(cert, valid_min))


def check_or_generate_account_key(args, existing):
    """Check or generate account key."""
    if existing is None:
        logger.info('Generating new account key')
        return jose.JWKRSA(key=rsa.generate_private_key(
            public_exponent=args.account_key_public_exponent,
            key_size=args.account_key_size,
            backend=default_backend(),
        ))
    return existing


def registered_client(args, existing_account_key):
    """Create ACME client, register if necessary."""
    key = check_or_generate_account_key(args, existing_account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    if args.email is None:
        logger.warning('--email was not provided; ACME CA will have no '
                       'way of contacting you.')
    new_reg = messages.NewRegistration.from_data(email=args.email)
    try:
        regr = client.register(new_reg)
    except acme_errors.ConflictError as error:
        logger.debug('Client already registered: %s', error.location)
    else:
        if regr.terms_of_service is not None:
            logger.info("By using simp_le, you implicitly agree to the "
                        "CA's terms of service: %s", regr.terms_of_service)
            client.agree_to_tos(regr)

    return client


def get_certr(client, csr, authorizations):
    """Get Certificate Resource for specified CSR and authorizations."""
    try:
        certr, _ = client.poll_and_request_issuance(
            jose.ComparableX509(csr), authorizations.values(),
            # https://github.com/letsencrypt/letsencrypt/issues/1719
            max_attempts=(10 * len(authorizations)))
    except acme_errors.PollError as error:
        if error.timeout:
            logger.error(
                'Timed out while waiting for CA to verify '
                'challenge(s) for the following authorizations: %s',
                ', '.join(authzr.uri for _, authzr in error.exhausted)
            )

        invalid = [authzr for authzr in six.itervalues(error.updated)
                   if authzr.body.status == messages.STATUS_INVALID]
        if invalid:
            logger.error("CA marked some of the authorizations as invalid, "
                         "which likely means it could not access "
                         "http://example.com/.well-known/acme-challenge/X. "
                         "Did you set correct path in -d example.com:path "
                         "or --default_root? Are all your domains accessible "
                         "from the internet? Please check your domains' DNS "
                         "entries, your host's network/firewall setup and "
                         "your webserver config. If a domain's DNS entry has "
                         "both A and AAAA fields set up, some CAs such as "
                         "Let's Encrypt will perform the challenge validation "
                         "over IPv6. If your DNS provider does not answer "
                         "correctly to CAA records request, Let's Encrypt "
                         "won't issue a certificate for your domain (see "
                         "https://letsencrypt.org/docs/caa/). Failing "
                         "authorizations: %s",
                         ', '.join(authzr.uri for authzr in invalid))

        raise Error('Challenge validation has failed, see error log.')
    return certr


def persist_new_data(args, existing_data):
    """Issue and persist new key/cert/chain."""
    roots = compute_roots(args.vhosts, args.default_root)
    logger.debug('Computed roots: %r', roots)

    client = registered_client(args, existing_data.account_key)

    authorizations = dict(
        (vhost.name, client.request_domain_challenges(vhost.name))
        for vhost in args.vhosts
    )
    if any(supported_challb(auth) is None
           for auth in six.itervalues(authorizations)):
        raise Error('CA did not offer http-01-only challenge combo. '
                    'This client is unable to solve any other challenges.')

    for name, auth in six.iteritems(authorizations):
        challb = supported_challb(auth)
        response, validation = challb.response_and_validation(client.key)
        save_validation(roots[name], challb, validation)

        client.answer_challenge(challb, response)

    if args.reuse_key and existing_data.key is not None:
        logger.info('Reusing existing certificate private key')
        key = existing_data.key
    else:
        logger.info('Generating new certificate private key')
        key = storage.ComparablePKey(utils.gen_pkey(args.cert_key_size))
    csr = utils.gen_csr(key.wrapped,
                        [vhost.name.encode() for vhost in args.vhosts])
    try:
        certr = get_certr(client, csr, authorizations)
        persist_data(args, existing_data, new_data=storage.IOPlugin.Data(
            account_key=client.key, key=key,
            cert=certr.body, chain=client.fetch_chain(certr)))
    except Error as error:
        persist_data(args, existing_data, new_data=storage.IOPlugin.Data(
            account_key=client.key, key=None, cert=None, chain=None))
        raise error
    finally:
        for name, auth in six.iteritems(authorizations):
            challb = supported_challb(auth)
            remove_validation(roots[name], challb)


def revoke(args):
    """Revoke certificate."""
    existing_data = load_existing_data(args.ioplugins)
    if existing_data.cert is None:
        raise Error('No existing certificate')

    key = check_or_generate_account_key(args, existing_data.account_key)
    net = acme_client.ClientNetwork(key, user_agent=args.user_agent)
    client = acme_client.Client(directory=args.server, key=key, net=net)
    client.revoke(existing_data.cert, rsn=0)
    return 0
