from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone
import ipaddress

class Cert:
    def __init__(self, assymetric_algorithm = rsa, a_a_parameters = {"public_exponent":65537, "key_size":2048}):

        # Generate CA private key
        ca_key = assymetric_algorithm.generate_private_key(**a_a_parameters)

        # Build CA certificate
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"My Cookie CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Cookies Inc."),
        ])

        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None), critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )

        # Save CA private key
        with open("ca_key.pem", "wb") as f:
            f.write(ca_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()  # Add encryption if desired
            ))

        # Save CA certificate
        with open("ca_cert.pem", "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
        self.key = ca_key
        self.cert = ca_cert
        self.subject = ca_subject

    def leaf(self, assymetric_algorithm = rsa, a_a_parameters = {"public_exponent":65537, "key_size":2048}):

        # Generate website private key
        web_key = assymetric_algorithm.generate_private_key(**a_a_parameters)

        # CSR (Certificate Signing Request)
        web_subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, u"cookies.local"),  # Use your local domain/IP
        ])

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            web_subject
        ).sign(web_key, hashes.SHA256())

        # Sign the CSR with CA key to get a certificate
        web_cert = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(self.cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=825))
            .add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName(u"cookies.local"),  # Add alternative names if needed
                    x509.IPAddress(ipaddress.IPv4Address("192.168.227.128")),  # Your local IP
                ]),
                critical=False,
            )
            .sign(self.key, hashes.SHA256())
        )

        # Save website key and cert
        with open("web_key.pem", "wb") as f:
            f.write(web_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()  # Use encryption if desired
            ))

        with open("web_cert.pem", "wb") as f:
            f.write(web_cert.public_bytes(serialization.Encoding.PEM))

        return {"key":web_key, "cert":web_cert, "subject":web_subject}

if __name__ == "__main__":
    test = Cert()
    test.leaf()