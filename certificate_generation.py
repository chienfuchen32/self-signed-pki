import os
import sys
from random import random

from OpenSSL.crypto import (
    X509, X509Req, PKey, X509Extension,
    dump_certificate, dump_privatekey,
    load_certificate, load_privatekey,
    FILETYPE_PEM, FILETYPE_ASN1, TYPE_RSA
)


# File
CURRENT_PATH = os.path.dirname(os.path.abspath(__file__))
CLIENT_CRT_FILE_NAME = 'client.crt'
CLIENT_KEY_FILE_NAME = 'client.key'
SERVER_CRT_FILE_NAME = 'server.crt'
SERVER_KEY_FILE_NAME = 'server.key'
CA_CRT_FILE_NAME = 'ca.crt'
CA_KEY_FILE_NAME = 'ca.key'

# X509
RSA_KEY_LENGTH = 2048
DIGITAL_SIGNATURE_ALGORITHM = 'sha256WithRSAEncryption'

CA_ISSUER_C = 'TW'
CA_ISSUER_ST = 'TW'
CA_ISSUER_L = 'TPE'
CA_ISSUER_O = 'foobar.com'
CA_ISSUER_OU = 'OU'
CA_ISSUER_CN = 'rootCA'
CA_ISSUER_EMAILADDRESS = 'svc@foobar.com'
CA_CERTIFICATE_VALID_TIME = 30 * 365 * 24 * 60 * 60 # 30 * 365 * 24 * 60 * 60 seconds

SERVER_SUBJECT_C = 'TW'
SERVER_SUBJECT_ST = 'TW'
SERVER_SUBJECT_L = 'TPE'
SERVER_SUBJECT_O = 'foobar.com'
SERVER_SUBJECT_OU = 'OU'
SERVER_SUBJECT_CN = '*.foobar.com'
SERVER_SUBJECT_EMAILADDRESS = 'svc@foobar.com'
SERVER_CERTIFICATE_VALID_TIME = 10 * 365 * 24 * 60 * 60 # 10 * 365 * 24 * 60 * 60 seconds

CLIENT_SUBJECT_C = 'TW'
CLIENT_SUBJECT_ST = 'TW'
CLIENT_SUBJECT_L = 'TPE'
CLIENT_SUBJECT_O = 'foobar.com'
CLIENT_SUBJECT_OU = 'OU'
CLIENT_SUBJECT_CN = 'client'
CLIENT_SUBJECT_EMAILADDRESS = 'svc@foobar.com'
CLIENT_CERTIFICATE_VALID_TIME = 5 * 365 * 24 * 60 * 60 # 10 * 365 * 24 * 60 * 60 seconds


class CertificateSigning():
    '''
    This class applied PyOpenSSL X509 certificate signing
    procedure as followed openssl cli example:
    ------------------------------------
    # [CA]
    openssl genrsa -out ca.key 1024 && openssl req -new -x509 -sha1 -days 1826 -key ca.key -out ca.crt -subj "/C=TW/ST=TW/L=TPE/O=foobar.com/OU=OU/CN=rootCA/emailAddress=svc@foobar.com"

    # [SERVER]
    openssl genrsa -out server.key 1024 && openssl req -new -out server.csr -key server.key -subj "/C=TW/ST=TW/L=TPE/O=foobar.com/OU=OU/CN=*.foobar.com/emailAddress=svc@foobar.com" && openssl x509 -req -sha1 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 360

    # [CLIENT]
    openssl genrsa -out client.key 1024 && openssl req -new -out client.csr -key client.key -subj "/C=TW/ST=TW/L=TPE/O=foobar.com/OU=OU/CN=client/emailAddress=svc@foobar.com" && openssl x509 -req -sha1 -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 360
    ------------------------------------
    '''
    def __init__(self):
        self._ca_pkey_file = os.path.join(CURRENT_PATH, CA_KEY_FILE_NAME)
        with open(self._ca_pkey_file, 'rt') as f:
            self._key_ca = load_privatekey(FILETYPE_PEM, f.read())
        self._ca_crt_file = os.path.join(CURRENT_PATH, CA_CRT_FILE_NAME)
        with open(self._ca_crt_file, 'rt') as f:
            self.cert_ca = load_certificate(FILETYPE_PEM, f.read())

    def _dump_cert_key_file(self, cert=X509(), pkey=PKey(),
                            cert_file='',
                            pkey_file=''):
        """Dump an X509 certificate and key as file

        Args:
            cert (`X509`): X509 certificate object
            pkey (`PKey`): DSA or RSA pubKey/private pair object
            cert_file (str): certificate filename with path
            pkey_file (str): key pair filename with path
        """
        with open(cert_file, 'wb') as f:
            f.write(dump_certificate(FILETYPE_PEM, cert))
        with open(pkey_file, 'wb') as f:
            f.write(dump_privatekey(FILETYPE_PEM, pkey))

    def _gen_ca_file(self, second_adj_not_before=0,
                     second_adj_not_after=CA_CERTIFICATE_VALID_TIME):
        # [CA]
        cert_ca = X509()
        subject = cert_ca.get_subject()
        subject.C = CA_ISSUER_C
        subject.ST = CA_ISSUER_ST
        subject.L = CA_ISSUER_L
        subject.O = CA_ISSUER_O
        subject.OU = CA_ISSUER_OU
        subject.CN = CA_ISSUER_CN
        subject.emailAddress = CA_ISSUER_EMAILADDRESS
        cert_ca.set_serial_number(int(random() * sys.maxsize))
        cert_ca.set_version(2)
        cert_ca.gmtime_adj_notBefore(second_adj_not_before)
        cert_ca.gmtime_adj_notAfter(second_adj_not_after)
        cert_ca.set_issuer(subject)
        cert_ca.set_subject(subject)
        cert_ca.set_pubkey(self._key_ca)
        cert_ca.add_extensions([
            X509Extension(b'basicConstraints', False, b'CA:TRUE'),
            X509Extension(b'subjectKeyIdentifier', False, b'hash',
                          subject=cert_ca)
        ])
        cert_ca.add_extensions([
            X509Extension(b'authorityKeyIdentifier', False,
                          b'keyid:always', issuer=cert_ca)
        ])
        cert_ca.sign(self._key_ca, DIGITAL_SIGNATURE_ALGORITHM)

        self._dump_cert_key_file(cert_ca, self._key_ca,
                                 self._ca_crt_file, self._ca_pkey_file)

    def gen_server_file(self, second_adj_not_before=0,
                        second_adj_not_after=SERVER_CERTIFICATE_VALID_TIME):
        pkey = PKey()

        _server_pkey_file = os.path.join(CURRENT_PATH, SERVER_KEY_FILE_NAME)
        pkey.generate_key(TYPE_RSA, RSA_KEY_LENGTH)
        csr = X509Req()
        csr.set_version(2)
        subject = csr.get_subject()
        subject.C = SERVER_SUBJECT_C
        subject.ST = SERVER_SUBJECT_ST
        subject.L = SERVER_SUBJECT_L
        subject.O = SERVER_SUBJECT_O
        subject.OU = SERVER_SUBJECT_OU
        subject.CN = SERVER_SUBJECT_CN
        subject.emailAddress = SERVER_SUBJECT_EMAILADDRESS
        csr.add_extensions([
            X509Extension(b'keyUsage', False,
                          b'Digital Signature, Key Encipherment'),
            X509Extension(b'basicConstraints', False, b'CA:FALSE'),
        ])
        '''
        san_list = [
            'IP:10.136.216.30',
            f'DNS:{SERVER_SUBJECT_CN}'
        ]
        csr.add_extensions([
            X509Extension(b'subjectAltName', False,
                          ", ".join(san_list).encode())
        ])
        '''

        csr.set_pubkey(pkey)
        csr.sign(pkey, DIGITAL_SIGNATURE_ALGORITHM)
        cert = self._sign_by_ca(csr, second_adj_not_before,
                                second_adj_not_after)
        server_crt_file = os.path.join(CURRENT_PATH, SERVER_CRT_FILE_NAME)
        self._dump_cert_key_file(cert, pkey, server_crt_file,
                                 _server_pkey_file)

    def _sign_by_ca(self, csr=None,
                    second_adj_not_before=0,
                    second_adj_not_after=CLIENT_CERTIFICATE_VALID_TIME):
        '''
        Args:
            csr (`X509Req`): An X.509 certificate signing requests.
            second_adj_not_before (int): Adjust the timestamp on which the
                certificate starts being valid.
            second_adj_not_after (int): Adjust the time stamp on which the
                certificate stops being valid.

        Returns (`X509`)
        '''
        if csr is None:
            return None
        cert = X509()
        cert.set_serial_number(int(random() * sys.maxsize))
        cert.set_version(2)
        cert.gmtime_adj_notBefore(second_adj_not_before)
        cert.gmtime_adj_notAfter(second_adj_not_after)
        cert.set_issuer(self.cert_ca.get_issuer())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.add_extensions(csr.get_extensions())
        cert.sign(self._key_ca, DIGITAL_SIGNATURE_ALGORITHM)
        return cert

    def _gen_client_csr(self):
        '''Generate a public/private key pair and X509 signing request.
        Returns: (`X509Req`), (`PKey`)
        '''
        pkey = PKey()
        pkey.generate_key(TYPE_RSA, RSA_KEY_LENGTH)
        csr = X509Req()
        csr.set_version(2)
        subject = csr.get_subject()
        subject.C = CLIENT_SUBJECT_C
        subject.ST = CLIENT_SUBJECT_ST
        subject.L = CLIENT_SUBJECT_L
        subject.O = CLIENT_SUBJECT_O
        subject.OU = CLIENT_SUBJECT_OU
        subject.CN = CLIENT_SUBJECT_CN
        subject.emailAddress = CLIENT_SUBJECT_EMAILADDRESS
        csr.set_pubkey(pkey)
        csr.sign(pkey, DIGITAL_SIGNATURE_ALGORITHM)
        return csr, pkey

    def gen_client_file(self,
                        crt_file='/{}/{}'.format(CURRENT_PATH, CLIENT_CRT_FILE_NAME),
                        key_file='/{}/{}'.format(CURRENT_PATH, CLIENT_KEY_FILE_NAME),
                        second_adj_not_before=0,
                        second_adj_not_after=CLIENT_CERTIFICATE_VALID_TIME):
        '''Generate CA signed certificate, key pair file
        Args:
            cert_file (str): certificate filename with path
            pkey_file (str): key pair filename with path
            second_adj_not_before (int): Adjust the timestamp on which the
                certificate starts being valid.
            second_adj_not_after (int): Adjust the time stamp on which the
                certificate stops being valid.
        '''
        csr, pkey = self._gen_client_csr()
        cert = self._sign_by_ca(csr, second_adj_not_before,
                                second_adj_not_after)
        self._dump_cert_key_file(cert, pkey, crt_file, key_file)


if __name__ == '__main__':
    certificate_signing = CertificateSigning()
    certificate_signing.gen_server_file()
    certificate_signing.gen_client_file()
