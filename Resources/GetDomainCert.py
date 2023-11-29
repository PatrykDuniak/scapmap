import socket
import ssl
import re
from .IPinterpreter import IPinterpreter

class GetDomainCert(IPinterpreter):
    def __init__(self, targets, port=443):
        super().__init__(targets)
        self.port=port

    def scrap_http(self):
        pattern = r"https?://(www\.)?"
        domain = re.sub(pattern, '', self._targets)
        return domain

    def get_domain_cert_info(self):
        context = ssl.create_default_context()
        self._targets = self.scrap_http()
        with socket.create_connection((self._targets, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self._targets) as ssock:
                cert_data = ssock.getpeercert()
                try:
                    print("Subject:")
                    for attr in cert_data['subject']:
                        print(f"{attr[0][0]}: {attr[0][1]}")

                    print("\nIssuer:")
                    for attr in cert_data['issuer']:
                        print(f"{attr[0][0]}: {attr[0][1]}")

                    print("\nVersion:", cert_data['version'])
                    print("Serial Number:", cert_data['serialNumber'])
                    print("Not Before:", cert_data['notBefore'])
                    print("Not After:", cert_data['notAfter'])

                    print("\nSubject Alternative Names:")
                    for name in cert_data['subjectAltName']:
                        print(f"{name[0]}: {name[1]}")

                    print("\nOCSP:", cert_data['OCSP'][0])
                    print("CA Issuers:", cert_data['caIssuers'][0])
                    print("CRL Distribution Points:", cert_data['crlDistributionPoints'][0])
                except KeyError:
                    print ('None? Site without cert.')

    def get_domain_raw_cert(self):
        self._targets = self.scrap_http()
        context = ssl.create_default_context()
        with socket.create_connection((self._targets, self.port)) as sock:
            with context.wrap_socket(sock, server_hostname=self._targets) as ssock:
                cert_data = ssock.getpeercert()
                print("Serial Number:", cert_data['serialNumber'])
                print("\nVersion:", cert_data['version'])
                cert_bin = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(binary_form=True))
                print(cert_bin)

