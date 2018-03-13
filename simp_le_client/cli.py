"""simp_le cli"""
import argparse
import os
import re
import sys
import traceback

from acme import messages

from simp_le_client import client
from simp_le_client import log
from simp_le_client import tests
from simp_le_client import storage


class Error(Exception):
    """simp_le error."""


def create_parser():
    """Create argument parser."""
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        usage=argparse.SUPPRESS, add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog='See %s for more info.' % client.URL,
    )

    general = parser.add_argument_group()
    general.add_argument(
        '-v', '--verbose', action='store_true', default=False,
        help='Increase verbosity of the logging.',
    )

    modes = parser.add_argument_group()
    modes.add_argument(
        '-h', '--help', action='store_true',
        help='Show this help message and exit.',
    )
    modes.add_argument(
        '--version', action='store_true',
        help='Display version and exit.'
    )
    modes.add_argument(
        '--revoke', action='store_true', default=False,
        help='Revoke existing certificate')
    modes.add_argument(
        '--test', action='store_true', default=False,
        help='Run tests and exit.',
    )
    modes.add_argument(
        '--integration_test', action='store_true', default=False,
        help='Run integration tests and exit.',
    )

    manager = parser.add_argument_group(
        'Webroot manager', description='This client is just a '
        'sophisticated manager for $webroot/'
        + client.challenges.HTTP01.URI_ROOT_PATH + '. You can (optionally) '
        'specify `--default_root`, and override per-vhost with '
        '`-d example.com:/var/www/other_html` syntax.',
    )
    manager.add_argument(
        '-d', '--vhost', dest='vhosts', action='append',
        help='Domain name that will be included in the certificate. '
        'Must be specified at least once.', metavar='DOMAIN:PATH',
        type=client.Vhost.decode,
    )
    manager.add_argument(
        '--default_root', help='Default webroot path.', metavar='PATH',
    )

    io_group = parser.add_argument_group('Certificate data files')
    io_group.add_argument(
        '-f', dest='ioplugins', action='append', default=[],
        metavar='PLUGIN', choices=sorted(storage.IOPlugin.registered),
        help='Input/output plugin of choice, can be specified multiple '
        'times and, in fact, it should be specified as many times as it '
        'is necessary to cover all components: key, certificate, chain. '
        'Allowed values: %s.' % ', '.join(sorted(storage.IOPlugin.registered)),
    )
    io_group.add_argument(
        '--cert_key_size', type=int, default=4096, metavar='BITS',
        help='Certificate key size. Fresh key is created for each renewal.',
    )
    io_group.add_argument(
        '--valid_min', type=int,
        default=client.DEFAULT_VALID_MIN, metavar='SECONDS',
        help='Minimum validity of the resulting certificate.',
    )
    io_group.add_argument(
        '--reuse_key', action='store_true', default=False,
        help='Reuse private key if it was previously persisted.',
    )

    reg = parser.add_argument_group(
        'Registration', description='This client will automatically '
        'register an account with the ACME CA specified by `--server`.'
    )
    reg.add_argument(
        '--account_key_public_exponent', type=int, default=65537,
        metavar='BITS', help='Account key public exponent value.',
    )
    reg.add_argument(
        '--account_key_size', type=int, default=4096, metavar='BITS',
        help='Account key size in bits.',
    )
    reg.add_argument(
        '--email', help='Email address. CA is likely to use it to '
        'remind about expiring certificates, as well as for account '
        'recovery. Therefore, it\'s highly recommended to set this '
        'value.',
    )

    http = parser.add_argument_group(
        'HTTP', description='Configure properties of HTTP requests and '
        'responses.',
    )
    http.add_argument(
        '--user_agent', default=('simp_le/' + client.VERSION), metavar='NAME',
        help='User-Agent sent in all HTTP requests. Override with '
        '--user_agent "" if you want to protect your privacy.',
    )
    http.add_argument(
        '--server', metavar='URI', default=client.LE_PRODUCTION_URI,
        help='Directory URI for the CA ACME API endpoint.',
    )

    return parser


def main_with_exceptions(cli_args):
    # pylint: disable=too-many-return-statements
    """Run the script, throw exceptions on error."""
    parser = create_parser()
    try:
        args = parser.parse_args(cli_args)
    except SystemExit:
        return client.EXIT_ERROR

    if args.test:  # --test
        return tests.cli_test(args)
    elif args.integration_test:  # --integration_test
        return tests.integration_test(args)
    elif args.help:  # --help
        parser.print_help()
        return client.EXIT_HELP_VERSION_OK
    elif args.version:  # --version
        sys.stdout.write('%s %s\n' % (os.path.basename(sys.argv[0]),
                                      client.VERSION))
        return client.EXIT_HELP_VERSION_OK

    log.setup_logging(args.verbose)
    log.logger.debug('%r parsed as %r', cli_args, args)

    if args.revoke:  # --revoke
        return client.revoke(args)

    if args.vhosts is None:
        raise Error('You must set at least one -d/--vhost')
    client.check_plugins_persist_all(args.ioplugins)

    if args.email is not None:
        match = re.match(r'.+@[A-Za-z0-9._-]+', args.email)
        if not match:
            raise Error("The email address you provided ({0}) does not appear"
                        "to be valid.".format(args.email))

    existing_data = client.load_existing_data(args.ioplugins)
    if client.valid_existing_cert(existing_data.cert,
                                  args.vhosts, args.valid_min):
        log.logger.info('Certificates already exist and renewal is not '
                        'necessary, exiting with status code %d.',
                        client.EXIT_NO_RENEWAL)
        return client.EXIT_NO_RENEWAL

    client.persist_new_data(args, existing_data)
    return client.EXIT_RENEWAL


def exit_with_error(message):
    """Print `message` and debugging tips to STDERR, exit with EXIT_ERROR."""
    sys.stderr.write('%s\n\nDebugging tips: -v improves output verbosity. '
                     'Help is available under --help.\n' % message)
    return client.EXIT_ERROR


def main(cli_args=tuple(sys.argv[1:])):     # tuple avoids a pylint warning
                                            # about (mutable) list as default
                                            # argument.
    """Run the script, with exceptions caught and printed to STDERR."""
    # logging (handler) is not set up yet, use STDERR only!
    try:
        return main_with_exceptions(cli_args)
    except Error as error:
        return exit_with_error(error)
    except messages.Error as error:
        return exit_with_error('ACME server returned an error: %s\n' % error)
    except BaseException as error:  # pylint: disable=broad-except
        # maintain manifest invariant: `exit 1` iff renewal not
        # necessary, `exit 2` iff error
        traceback.print_exc(file=sys.stderr)
        return exit_with_error(
            '\nUnhandled error has happened, traceback is above')


if __name__ == '__main__':
    raise SystemExit(main())
