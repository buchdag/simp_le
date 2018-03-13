"""simp_le utilities"""
import datetime

import OpenSSL
import pytz


def asn1_generalizedtime_to_dt(timestamp):
    """Convert ASN.1 GENERALIZEDTIME to datetime.

    Useful for deserialization of `OpenSSL.crypto.X509.get_notAfter` and
    `OpenSSL.crypto.X509.get_notAfter` outputs.

    TODO: Implement remaining two formats: *+hhmm, *-hhmm.

    >>> asn1_generalizedtime_to_dt('201511150803Z')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=<UTC>)
    >>> asn1_generalizedtime_to_dt('201511150803+1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(912))
    >>> asn1_generalizedtime_to_dt('201511150803-1512')
    datetime.datetime(2015, 11, 15, 8, 0, 3, tzinfo=pytz.FixedOffset(-912))
    """
    dt = datetime.datetime.strptime(  # pylint: disable=invalid-name
        timestamp[:12], '%Y%m%d%H%M%S')
    if timestamp.endswith('Z'):
        tzinfo = pytz.utc
    else:
        sign = -1 if timestamp[-5] == '-' else 1
        tzinfo = pytz.FixedOffset(
            sign * (int(timestamp[-4:-2]) * 60 + int(timestamp[-2:])))
    return tzinfo.localize(dt)


def componentwise_or(first, second):
    """Componentwise OR.

    >>> componentwise_or((False, False), (False, False))
    (False, False)
    >>> componentwise_or((True, False), (False, False))
    (True, False)
    >>> componentwise_or((True, False), (False, True))
    (True, True)
    """
    return tuple(x or y for x, y in zip(first, second))


def gen_pkey(bits):
    """Generate a private key.

    >>> gen_pkey(1024)
    <OpenSSL.crypto.PKey object at 0x...>

    Args:
      bits: Bit size of the key.

    Returns:
      Freshly generated private key.
    """
    assert bits >= 1024
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, bits)
    return pkey


def gen_csr(pkey, domains, sig_hash='sha256'):
    """Generate a CSR.

    >>> [str(domain) for domain in crypto_util._pyopenssl_cert_or_req_san(
    ...     gen_csr(gen_pkey(1024), [b'example.com', b'example.net']))]
    ['example.com', 'example.net']

    Args:
      pkey: Private key.
      domains: List of domains included in the cert.
      sig_hash: Hash used to sign the CSR.

    Returns:
      Generated CSR.
    """
    assert domains, 'Must provide one or more hostnames for the CSR.'
    req = OpenSSL.crypto.X509Req()
    req.add_extensions([
        OpenSSL.crypto.X509Extension(
            b'subjectAltName',
            critical=False,
            value=b', '.join(b'DNS:' + d for d in domains)
        ),
    ])
    req.set_pubkey(pkey)

    # pre-1.0.2 version of OpenSSL the generated CSR will contain a
    # zero-length Version field which will cause some strict parsers
    # (e.g. the one in Golang, used by Boulder) to fail.
    req.set_version(2)

    req.sign(pkey, sig_hash)
    return req
