"""simp_le test suite"""
import contextlib
import doctest
import hashlib
import importlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
import unittest

import josepy as jose
import mock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from acme import crypto_util

from simp_le_client import client
from simp_le_client import log
from simp_le_client import storage
from simp_le_client import utils


class Error(Exception):
    """simp_le error."""


class UnitTestCase(unittest.TestCase):
    """simp_le unit test case."""

    class AssertRaisesContext(object):
        """Context for assert_raises."""
        # pylint: disable=too-few-public-methods

        def __init__(self):
            self.error = None

    @contextlib.contextmanager
    def assert_raises(self, exc):
        """Assert raises context manager."""
        context = self.AssertRaisesContext()
        try:
            yield context
        except exc as error:
            context.error = error
        else:
            self.fail('Expected exception (%s) not raised' % exc)

    def assert_raises_regexp(self, exc, regexp, func, *args, **kwargs):
        """Assert raises that tests exception message against regexp."""
        with self.assert_raises(exc) as context:
            func(*args, **kwargs)
        msg = str(context.error)
        self.assertTrue(re.match(regexp, msg) is not None,
                        "Exception message (%s) doesn't match "
                        "regexp (%s)" % (msg, regexp))

    def assert_raises_error(self, *args, **kwargs):
        """Assert raises simp_le error with given message."""
        self.assert_raises_regexp(Error, *args, **kwargs)

    @staticmethod
    def check_logs(level, pattern, func):
        """Check whether func logs a message matching pattern.

        ``pattern`` is a regular expression to match the logs against.
        ``func`` is the function to call.
        ``level`` is the logging level to set during the function call.

        Returns True if there is a match, False otherwise.
        """
        log_msgs = []

        class TestHandler(logging.Handler):
            """Log handler that saves logs in ``log_msgs``."""

            def emit(self, record):
                log_msgs.append(record.msg % record.args)

        handler = TestHandler(level=level)
        log.logger.addHandler(handler)

        try:
            func()
            for msg in log_msgs:
                if re.match(pattern, msg) is not None:
                    return True
            return False
        finally:
            log.logger.removeHandler(handler)


class SplitPemsTest(UnitTestCase):
    """split_pems static method test."""
    # this is a test suite | pylint: disable=missing-docstring

    def test_split_pems(self):
        pem = b'\n-----BEGIN FOO BAR-----\nfoo\nbar\n-----END FOO BAR-----'
        result = len(list(storage.OpenSSLIOPlugin.split_pems(pem * 3)))
        self.assertEqual(result, 3)
        result = list(storage.OpenSSLIOPlugin.split_pems(b''))
        self.assertEqual(result, [])


class PluginIOTestMixin(object):
    """Common plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    PLUGIN_CLS = NotImplemented

    def __init__(self, *args, **kwargs):
        super(PluginIOTestMixin, self).__init__(*args, **kwargs)

        raw_key = utils.gen_pkey(1024)
        self.all_data = storage.IOPlugin.Data(
            account_key=jose.JWKRSA(key=rsa.generate_private_key(
                public_exponent=65537, key_size=1024,
                backend=default_backend(),
            )),
            key=storage.ComparablePKey(raw_key),
            cert=jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['a'])),
            chain=[
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['b'])),
                jose.ComparableX509(crypto_util.gen_ss_cert(raw_key, ['c'])),
            ],
        )
        self.key_data = storage.IOPlugin.EMPTY_DATA._replace(
            key=self.all_data.key)

    def setUp(self):  # pylint: disable=invalid-name
        self.root = tempfile.mkdtemp()
        self.path = os.path.join(self.root, 'plugin')
        # pylint: disable=not-callable
        self.plugin = self.PLUGIN_CLS(path=self.path)

    def tearDown(self):  # pylint: disable=invalid-name
        shutil.rmtree(self.root)


class FileIOPluginTestMixin(PluginIOTestMixin):
    """Common FileIO plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    PEM = b'\n-----BEGIN FOO BAR-----\nfoo\nbar\n-----END FOO BAR-----'

    def test_empty(self):
        self.assertEqual(storage.IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_load_empty_or_bad_content(self):
        self.assert_raises_error('.*the file might be empty or corrupt.',
                                 self.plugin.load_from_content, b'')
        self.assert_raises_error('.*the file might be empty or corrupt.',
                                 self.plugin.load_from_content, self.PEM)

    def test_save_ignore_unpersisted(self):
        self.plugin.save(self.all_data)
        self.assertEqual(self.plugin.load(), storage.IOPlugin.Data(
            *(data if persist else None for persist, data in
              zip(self.plugin.persisted(), self.all_data))))


class ChainFileIOPluginTestMixin(FileIOPluginTestMixin):
    """Common Chain type FileIO plugins tests."""
    # this is a test suite | pylint: disable=missing-docstring

    def test_load_empty_or_bad_content(self):
        self.assert_raises_error('.*PEM encoded message.*',
                                 self.plugin.load_from_content, b'')
        self.assert_raises_error('.*the file might be empty or corrupt.',
                                 self.plugin.load_from_content, self.PEM * 3)


class KeyFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for KeyFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.KeyFile


class CertFileTest(FileIOPluginTestMixin, UnitTestCase):
    """Tests for CertFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.CertFile


class ChainFileTest(ChainFileIOPluginTestMixin, UnitTestCase):
    """Tests for ChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.ChainFile


class FullChainFileTest(ChainFileIOPluginTestMixin, UnitTestCase):
    """Tests for FullChainFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.FullChainFile


class FullFileTest(ChainFileIOPluginTestMixin, UnitTestCase):
    """Tests for FullFile."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.FullFile


class ExternalIOPluginTest(PluginIOTestMixin, UnitTestCase):
    """Tests for ExternalIOPlugin."""
    # this is a test suite | pylint: disable=missing-docstring
    PLUGIN_CLS = storage.ExternalIOPlugin

    def save_script(self, contents):
        with open(self.path, 'w') as external_plugin_file:
            external_plugin_file.write(contents)
        os.chmod(self.path, 0o700)

    def test_no_persisted_empty(self):
        self.save_script('#!/bin/sh')
        self.assertEqual(storage.IOPlugin.EMPTY_DATA, self.plugin.load())

    def test_missing_path_raises_error(self):
        self.assert_raises_error(
            'Failed to execute external script', self.plugin.load)

    def test_load_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.load)

    def test_save_nonzero_raises_error(self):
        self.save_script('#!/bin/sh\nfalse')
        self.assert_raises_error(
            '.*exited with non-zero code: 1', self.plugin.save, self.key_data)

    def one_file_script(self, persisted):
        path = os.path.join(self.root, 'pem')
        self.save_script("""\
#!/bin/sh
case $1 in
  save) cat - > {path};;
  load) [ ! -f {path} ] ||  cat {path};;
  persisted) echo {persisted};;
esac
""".format(path=path, persisted=persisted))
        return path

    def test_it(self):
        path = self.one_file_script('cert chain key account_key')
        # not yet persisted
        self.assertEqual(storage.IOPlugin.EMPTY_DATA, self.plugin.load())
        # save some data
        self.plugin.save(self.all_data)
        self.assertTrue(os.path.exists(path))
        # loading should return the persisted data back in
        self.assertEqual(self.all_data, self.plugin.load())


class PortNumWarningTest(UnitTestCase):
    """Tests relating to the port number warning."""

    def _check_warn(self, should_log, path):
        """test whether the supplied path triggers the port number warning.

        ``should_log`` is a boolean indicating whether or not we expect the
        path to trigger a warning.
        ``path`` is the webroot path to check.

        If ``should_log`` is inconsistent with the behavior of
        ``compute_roots`` given ``path``, the test fails.
        """
        return self.assertEqual(
            self.check_logs(
                logging.WARN,
                '.*looks like it is a port number.*',
                lambda: client.compute_roots([
                    client.Vhost('example.com', path),
                ], 'webroot')
            ),
            should_log,
        )

    def test_warn_port(self):
        """A bare port number triggers the warning."""
        self._check_warn(True, '8000')

    def test_warn_port_path(self):
        """``port_no:path`` triggers the warning."""
        self._check_warn(True, '8000:/webroot')

    def test_no_warn_path(self):
        """A bare path doesn't trigger the warning."""
        self._check_warn(False, '/my-web-root')

    def test_no_warn_bigport(self):
        """A number too big to be a port doesn't trigger the warning."""
        self._check_warn(False, '66000')


class TestLoader(unittest.TestLoader):
    """simp_le test loader."""

    def load_tests_from_subclass(self, subcls):
        """Load tests which subclass from specific test case class."""
        module = importlib.import_module('simp_le_client.tests')
        return self.suiteClass([
            self.loadTestsFromTestCase(getattr(module, attr))
            for attr in dir(module)
            if isinstance(getattr(module, attr), type)
            and issubclass(getattr(module, attr), subcls)])


def test_suite(args, suite):
    """Run a specific test suite."""
    return client.EXIT_TESTS_OK if unittest.TextTestRunner(
        verbosity=(2 if args.verbose else 1)).run(
            suite).wasSuccessful() else client.EXIT_ERROR


def cli_test(args):
    """Run tests (--test)."""
    return test_suite(args, unittest.TestSuite((
        TestLoader().load_tests_from_subclass(UnitTestCase),
        doctest.DocTestSuite(optionflags=(
            doctest.ELLIPSIS | doctest.IGNORE_EXCEPTION_DETAIL)),
    )))


def integration_test(args):
    """Run integration tests (--integration-test)."""
    return test_suite(
        args, unittest.defaultTestLoader.loadTestsFromTestCase(
            IntegrationTests))


class MainTest(UnitTestCase):
    """Unit tests for the CLI."""

    # this is a test suite | pylint: disable=missing-docstring
    CMD = ['simp_le']

    @classmethod
    def _run(cls, cmd):
        with open(os.devnull, 'wb') as silent:
            return subprocess.call(cmd, stdout=silent, stderr=silent)

    @mock.patch('sys.stdout')
    def test_exit_code_help_version_ok(self, dummy_stdout):
        # pylint: disable=unused-argument
        cmd = self.CMD
        self.assertEqual(
            client.EXIT_HELP_VERSION_OK, self._run(cmd + ['--help']))
        self.assertEqual(
            client.EXIT_HELP_VERSION_OK, self._run(cmd + ['--version']))

    @mock.patch('sys.stderr')
    def test_error_exit_codes(self, dummy_stderr):
        # pylint: disable=unused-argument
        cmd = self.CMD
        test_args = [
            # no args - no good
            [''],
            # unrecognized
            ['--bar'],
            # no vhosts
            ['-f account_key.json', '-f key.pem', '-f fullchain.pem'],
            # no root
            ['-f account_key.json', '-f key.pem',
             '-f fullchain.pem', '-d example.com'],
            # no root with multiple domains
            ['-f account_key.json', '-f key.pem', '-f fullchain.pem',
             '-d example.com:public_html', '-d www.example.com'],
            # invalid email
            ['-f account_key.json', '-f key.pem', '-f fullchain.pem'
             '-d example.com:public_html', '--email @wrong.com'],
        ]
        # missing plugin coverage
        test_args.extend([['-d example.com:public_html'] + rest for rest in [
            ['-f account_key.json'],
            ['-f key.pem'],
            ['-f account_key.json', '-f key.pem'],
            ['-f key.pem', '-f cert.pem'],
            ['-f key.pem', '-f chain.pem'],
            ['-f fullchain.pem'],
            ['-f cert.pem', '-f fullchain.pem'],
        ]])

        for args in test_args:
            args_str = ' '.join(args)
            self.assertEqual(
                client.EXIT_ERROR, self._run(cmd + args),
                'Wrong exit code for %s' % args_str)


@contextlib.contextmanager
def chdir(path):
    """Context manager that adjusts CWD."""
    old_path = os.getcwd()
    os.chdir(path)
    try:
        yield old_path
    finally:
        os.chdir(old_path)


class IntegrationTests(unittest.TestCase):
    """Integrations tests with Boulder.

    Prerequisites:
    - /etc/hosts:127.0.0.1 le.wtf
    - Boulder running on localhost:4000
    - Boulder verifying http-01 on port 5002
    """
    # this is a test suite | pylint: disable=missing-docstring

    SERVER = 'http://localhost:4000/directory'
    PORT = 5002

    @classmethod
    def _run(cls, cmd):
        args = ' '.join(cmd[1:])
        log.logger.debug('Running simp_le with the following args: %s', args)
        return subprocess.call(cmd)

    @classmethod
    @contextlib.contextmanager
    def _new_swd(cls):
        path = tempfile.mkdtemp()
        try:
            with chdir(path) as old_path:
                yield old_path, path
        finally:
            shutil.rmtree(path)

    @classmethod
    def get_stats(cls, *paths):
        def _single_path_stats(path):
            all_stats = os.stat(path)
            stats = dict(
                (name[3:], getattr(all_stats, name)) for name in dir(all_stats)
                # skip access (read) time, includes _ns.
                if name.startswith('st_') and not name.startswith('st_atime'))
            # st_*time has a second-granularity so it can't be
            # reliably used to prove that contents have changed or not
            with open(path, 'rb') as f:  # pylint: disable=invalid-name
                stats.update(checksum=hashlib.sha256(f.read()).hexdigest())
            return stats
        return dict((path, _single_path_stats(path)) for path in paths)

    def test_it(self):
        webroot = os.path.join(os.getcwd(), 'public_html')
        cmd = ["simp_le", "-v", "--server", (self.SERVER),
               "-f", "account_key.json", "-f", "key.pem",
               "-f", "full.pem"]
        files = ('account_key.json', 'key.pem', 'full.pem')
        with self._new_swd():
            webroot_fail_arg = ["-d", "le.wtf:%s" % os.getcwd()]
            self.assertEqual(client.EXIT_ERROR,
                             self._run(cmd + webroot_fail_arg))
            # Failed authorization should generate the account key anyway
            unchangeable_stats = self.get_stats(files[0])

            webroot_1_arg = ["-d", "le.wtf:%s" % webroot]
            self.assertEqual(client.EXIT_RENEWAL,
                             self._run(cmd + webroot_1_arg))
            # Account key should be kept from previous failed attempt
            self.assertEqual(unchangeable_stats, self.get_stats(files[0]))
            initial_stats = self.get_stats(*files)

            self.assertEqual(client.EXIT_NO_RENEWAL,
                             self._run(cmd + webroot_1_arg))
            # No renewal => no files should be touched
            # NB get_stats() would fail if file didn't exist
            self.assertEqual(initial_stats, self.get_stats(*files))

            self.assertEqual(client.EXIT_REVOKE_OK, self._run([
                "simp_le", "-v", "--server", (self.SERVER), "--revoke",
                "-f", "account_key.json", "-f", "full.pem"]))
            # Revocation shouldn't touch any files
            self.assertEqual(initial_stats, self.get_stats(*files))

            webroot_2_arg = ["-d", "le2.wtf:%s" % webroot]
            # Changing SANs should trigger "renewal"
            self.assertEqual(client.EXIT_RENEWAL,
                             self._run(cmd + webroot_1_arg + webroot_2_arg))
            # but it shouldn't unnecessarily overwrite the account key (#67)
            self.assertEqual(unchangeable_stats, self.get_stats(files[0]))
