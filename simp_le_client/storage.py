"""simp_le input/output plugins"""
import abc
import collections
import errno
import logging
import os
import re
import subprocess

import josepy as jose
import OpenSSL

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from simp_le_client.log import logger


class Error(Exception):
    """simp_le error."""


class ComparablePKey(object):  # pylint: disable=too-few-public-methods
    """Comparable key.

    Suppose you have the following keys with the same material:

    >>> pem = OpenSSL.crypto.dump_privatekey(
    ...     OpenSSL.crypto.FILETYPE_PEM, gen_pkey(1024))
    >>> k1 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)
    >>> k2 = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, pem)

    Unfortunately, in pyOpenSSL, equality is not well defined:

    >>> k1 == k2
    False

    Using `ComparablePKey` you get the equality relation right:

    >>> ck1, ck2 = ComparablePKey(k1), ComparablePKey(k2)
    >>> other_ckey = ComparablePKey(gen_pkey(1024))
    >>> ck1 == ck2
    True
    >>> ck1 == k1
    False
    >>> k1 == ck1
    False
    >>> other_ckey == ck1
    False

    Non-equalty is also well defined:

    >>> ck1 != ck2
    False
    >>> ck1 != k1
    True
    >>> k1 != ck1
    True
    >>> k1 != other_ckey
    True
    >>> other_ckey != ck1
    True

    Wrapepd key is available as well:

    >>> ck1.wrapped is k1
    True

    Internal implementation is not optimized for performance!
    """

    def __init__(self, wrapped):
        self.wrapped = wrapped

    def __ne__(self, other):
        return not self == other  # pylint: disable=unneeded-not

    def _dump(self):
        return OpenSSL.crypto.dump_privatekey(
            OpenSSL.crypto.FILETYPE_ASN1, self.wrapped)

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        # pylint: disable=protected-access
        return self._dump() == other._dump()


class IOPlugin(object):
    """Input/output plugin.

    In case of any problems, `persisted`, `load` and `save`
    methods should raise `Error`, for which message will be
    displayed directly to the user through STDERR (in `main`).

    """
    __metaclass__ = abc.ABCMeta

    Data = collections.namedtuple('IOPluginData', 'account_key key cert chain')
    """Plugin data.

    Unless otherwise stated, plugin data components are typically
    filled with the following data:

    - for `account_key`: private account key, an instance of `acme.jose.JWK`
    - for `key`: private key, an instance of `OpenSSL.crypto.PKey`
    - for `cert`: certificate, an instance of `OpenSSL.crypto.X509`
    - for `chain`: certificate chain, a list of `OpenSSL.crypto.X509` instances
    """

    EMPTY_DATA = Data(account_key=None, key=None, cert=None, chain=None)

    def __init__(self, path, **dummy_kwargs):
        self.path = path

    @abc.abstractmethod
    def persisted(self):
        """Which data is persisted by this plugin?

        This method must be overridden in subclasses and must return
        `IOPlugin.Data` with Boolean values indicating whether specific
        component is persisted by the plugin.
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def load(self):
        """Load persisted data.

        This method must be overridden in subclasses and must return
        `IOPlugin.Data`. For all non-persisted data it must set the
        corresponding component to `None`. If the data was not persisted
        previously, it must return `EMPTY_DATA` (note that it does not
        make sense for the plugin to set subset of the persisted
        components to not-None: this would mean that data was persisted
        only partially - if possible plugin should detect such condition
        and throw an `Error`).
        """
        raise NotImplementedError()

    @abc.abstractmethod
    def save(self, data):
        """Save data to file system.

        This method must be overridden in subclasses and must accept
        `IOPlugin.Data`. It must store all persisted components and
        ignore all non-persisted components. It is guaranteed that all
        persisted components are not `None`.
        """
        raise NotImplementedError()

    # Plugin registration magic
    registered = {}

    @classmethod
    def register(cls, **kwargs):
        """Register IO plugin."""
        def init_and_reg(plugin_cls):
            """Initialize plugin class and register."""
            plugin = plugin_cls(**kwargs)
            assert (os.path.sep not in plugin.path
                    and plugin.path not in ('.', '..'))
            cls.registered[plugin.path] = plugin
            return plugin_cls
        return init_and_reg


class FileIOPlugin(IOPlugin):
    """Plugin that saves/reads files on disk."""

    READ_MODE = 'rb'
    WRITE_MODE = 'wb'

    def load(self):
        logger.debug('Loading %s', self.path)
        try:
            with open(self.path, self.READ_MODE) as persist_file:
                content = persist_file.read()
        except IOError as error:
            if error.errno == errno.ENOENT:
                # file does not exist, so it was not persisted
                # previously
                return self.EMPTY_DATA
            raise
        return self.load_from_content(content)

    @abc.abstractmethod
    def load_from_content(self, content):
        """Load from file contents.

        This method must be overridden in subclasses. It will be called
        with the contents of the file read from `path` and should return
        whatever `IOPlugin.load` is meant to return.
        """
        raise NotImplementedError()

    def save_to_file(self, data):
        """Save data to file."""
        logger.info('Saving %s', self.path)
        try:
            with open(self.path, self.WRITE_MODE) as persist_file:
                persist_file.write(data)
        except OSError as error:
            logging.exception(error)
            raise Error('Error when saving {0}'.format(self.path))


class JWKIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IO Plugin that uses JWKs."""

    @classmethod
    def load_jwk(cls, data):
        """Load JWK."""
        return jose.JWKRSA.json_loads(data)

    @classmethod
    def load_pem_jwk(cls, data):
        """Load JWK encoded as PEM."""
        return jose.JWKRSA(key=serialization.load_pem_private_key(
            data, password=None, backend=default_backend()))

    @classmethod
    def dump_jwk(cls, jwk):
        """Dump JWK."""
        return jwk.json_dumps()

    @classmethod
    def dump_pem_jwk(cls, data):
        """Dump JWK as PEM."""
        return data.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).strip()


class OpenSSLIOPlugin(IOPlugin):  # pylint: disable=abstract-method
    """IOPlugin that uses pyOpenSSL.

    Args:
      typ: One of `OpenSSL.crypto.FILETYPE_*`, used in loading/dumping.
    """

    _PEMS_SEP = b'\n'

    def __init__(self, typ=OpenSSL.crypto.FILETYPE_PEM, **kwargs):
        self.typ = typ
        super(OpenSSLIOPlugin, self).__init__(**kwargs)

    @staticmethod
    def split_pems(data):
        """Split buffer comprised of PEM encoded (RFC 7468)."""
        pem_re_labelchar = r'[\x21-\x2c\x2e-\x7e]'
        pem_re = re.compile(
            (r"""
        ^-----BEGIN\ ((?:%s(?:[- ]?%s)*)?)\s*-----$
        .*?
        ^-----END\ \1-----\s*""" % (pem_re_labelchar,
                                    pem_re_labelchar)).encode(),
            re.DOTALL | re.MULTILINE | re.VERBOSE)
        for match in pem_re.finditer(data):
            yield match.group(0)

    def load_key(self, data):
        """Load private key."""
        try:
            key = OpenSSL.crypto.load_privatekey(self.typ, data)
        except OpenSSL.crypto.Error:
            raise Error("simp_le couldn't load a key from {0}; the "
                        "file might be empty or corrupt.".format(self.path))
        return ComparablePKey(key)

    def dump_key(self, data):
        """Dump private key."""
        return OpenSSL.crypto.dump_privatekey(self.typ, data.wrapped).strip()

    def load_cert(self, data):
        """Load certificate."""
        try:
            cert = OpenSSL.crypto.load_certificate(self.typ, data)
        except OpenSSL.crypto.Error:
            raise Error("simp_le couldn't load a certificate from {0}; the "
                        "file might be empty or corrupt.".format(self.path))
        return jose.ComparableX509(cert)

    def dump_cert(self, data):
        """Dump certificate."""
        return OpenSSL.crypto.dump_certificate(self.typ, data.wrapped).strip()


@IOPlugin.register(path='account_key.json')
class AccountKey(FileIOPlugin, JWKIOPlugin):
    """Account key IO Plugin using JWS."""

    # this is not a binary file
    READ_MODE = 'r'
    WRITE_MODE = 'w'

    def persisted(self):
        return self.Data(account_key=True, key=False, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(
            account_key=self.load_jwk(content),
            key=None,
            cert=None,
            chain=None,
        )

    def save(self, data):
        key = self.dump_jwk(data.account_key)
        return self.save_to_file(key)


@IOPlugin.register(path='key.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='key.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class KeyFile(FileIOPlugin, OpenSSLIOPlugin):
    """Private key file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=True, cert=False, chain=False)

    def load_from_content(self, content):
        return self.Data(
            account_key=None,
            key=self.load_key(content),
            cert=None,
            chain=None,
        )

    def save(self, data):
        key = self.dump_key(data.key)
        return self.save_to_file(key)


@IOPlugin.register(path='cert.der', typ=OpenSSL.crypto.FILETYPE_ASN1)
@IOPlugin.register(path='cert.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class CertFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=False)

    def load_from_content(self, content):
        return self.Data(
            account_key=None,
            key=None,
            cert=self.load_cert(content),
            chain=None,
        )

    def save(self, data):
        cert = self.dump_cert(data.cert)
        return self.save_to_file(cert)


@IOPlugin.register(path='chain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class ChainFile(FileIOPlugin, OpenSSLIOPlugin):
    """Certificate chain plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=False, chain=True)

    def load_from_content(self, content):
        pems = list(self.split_pems(content))
        if not pems:
            raise Error("No PEM encoded message was found in {0}; "
                        "at least 1 was expected.".format(self.path))
        return self.Data(
            account_key=None,
            key=None,
            cert=None,
            chain=[self.load_cert(cert) for cert in pems[0:]],
        )

    def save(self, data):
        pems = [self.dump_cert(cert) for cert in data.chain]
        return self.save_to_file(self._PEMS_SEP.join(pems))


@IOPlugin.register(path='fullchain.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullChainFile(FileIOPlugin, OpenSSLIOPlugin):
    """Full chain file plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=False, cert=True, chain=True)

    def load_from_content(self, content):
        pems = list(self.split_pems(content))
        if len(pems) < 2:
            raise Error("Not enough PEM encoded messages were found in {0}; "
                        "at least 2 were expected, found {1}."
                        .format(self.path, len(pems)))
        return self.Data(
            account_key=None,
            key=None,
            cert=self.load_cert(pems[0]),
            chain=[self.load_cert(cert) for cert in pems[1:]],
        )

    def save(self, data):
        pems = [self.dump_cert(data.cert)]
        pems.extend(self.dump_cert(cert) for cert in data.chain)
        return self.save_to_file(self._PEMS_SEP.join(pems))


@IOPlugin.register(path='full.pem', typ=OpenSSL.crypto.FILETYPE_PEM)
class FullFile(FileIOPlugin, OpenSSLIOPlugin):
    """Private key, certificate and chain plugin."""

    def persisted(self):
        return self.Data(account_key=False, key=True, cert=True, chain=True)

    def load_from_content(self, content):
        pems = list(self.split_pems(content))
        if len(pems) < 3:
            raise Error("Not enough PEM encoded messages were found in {0}; "
                        "at least 3 were expected, found {1}."
                        .format(self.path, len(pems)))
        return self.Data(
            account_key=None,
            key=self.load_key(pems[0]),
            cert=self.load_cert(pems[1]),
            chain=[self.load_cert(cert) for cert in pems[2:]],
        )

    def save(self, data):
        pems = [self.dump_key(data.key), self.dump_cert(data.cert)]
        pems.extend(self.dump_cert(cert) for cert in data.chain)
        return self.save_to_file(self._PEMS_SEP.join(pems))


@IOPlugin.register(path='external.sh', typ=OpenSSL.crypto.FILETYPE_PEM)
class ExternalIOPlugin(JWKIOPlugin, OpenSSLIOPlugin):
    """External IO Plugin.

    This plugin executes script that complies with the
    "persisted|load|save protocol":

    - whenever the script is called with `persisted` as the first
      argument, it should send to STDOUT a single line consisting of a
      subset of four keywords: `account_key`, `key`, `cert`, `chain`
      (in any order, separated by whitespace);

    - whenever the script is called with `load` as the first argument it
      shall write to STDOUT all persisted data as PEM encoded strings in
      the following order: account_key, key, certificate, certificates
      in the chain (from leaf to root). If some data is not persisted,
      it must be skipped in the output;

    - whenever the script is called with `save` as the first argument,
      it should accept data from STDIN and persist it. Data is encoded
      and ordered in the same way as in the `load` case.
    """

    @property
    def script(self):
        """Path to the script."""
        return os.path.join('.', self.path)

    def get_output_or_fail(self, command):
        """Get output or throw an exception in case of errors."""
        try:
            proc = subprocess.Popen(
                [self.script, command], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except (OSError, subprocess.CalledProcessError) as error:
            raise Error('Failed to execute external script: {0}'.format(error))

        stdout, stderr = proc.communicate()
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: {0}'
                        .format(proc.returncode))

        # Do NOT log `stdout` as it might contain secret material (in
        # case key is persisted)
        return stdout

    def persisted(self):
        """Call the external script and see which data is persisted."""
        output = self.get_output_or_fail('persisted').split()
        return self.Data(
            account_key=(b'account_key' in output),
            key=(b'key' in output),
            cert=(b'cert' in output),
            chain=(b'chain' in output),
        )

    def load(self):
        """Call the external script to retrieve persisted data."""
        pems = list(self.split_pems(self.get_output_or_fail('load')))
        if not pems:
            return self.EMPTY_DATA
        persisted = self.persisted()

        account_key = self.load_pem_jwk(
            pems.pop(0)) if persisted.account_key else None
        key = self.load_key(pems.pop(0)) if persisted.key else None
        cert = self.load_cert(pems.pop(0)) if persisted.cert else None
        chain = ([self.load_cert(cert_data) for cert_data in pems]
                 if persisted.chain else None)
        return self.Data(account_key=account_key, key=key,
                         cert=cert, chain=chain)

    def save(self, data):
        """Call the external script and send data to be persisted to STDIN."""
        persisted = self.persisted()
        output = []
        if persisted.account_key:
            output.append(self.dump_pem_jwk(data.account_key))
        if persisted.key:
            output.append(self.dump_key(data.key))
        if persisted.cert:
            output.append(self.dump_cert(data.cert))
        if persisted.chain:
            output.extend(self.dump_cert(cert) for cert in data.chain)

        logger.info('Calling `%s save` and piping data through', self.script)
        try:
            proc = subprocess.Popen(
                [self.script, 'save'], stdin=subprocess.PIPE,
                stdout=subprocess.PIPE)
        except OSError as error:
            logger.exception(error)
            raise Error(
                'There was a problem executing external IO plugin script')
        stdout, stderr = proc.communicate(self._PEMS_SEP.join(output))
        if stdout is not None:
            logger.debug('STDOUT: %s', stdout)
        if stderr is not None:
            logger.error('STDERR: %s', stderr)
        if proc.wait():
            raise Error('External script exited with non-zero code: {0}'
                        .format(proc.returncode))
