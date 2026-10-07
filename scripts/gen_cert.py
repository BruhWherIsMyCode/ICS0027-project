import datetime
import ipaddress
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

cert_dir = "certs"
os.makedirs(cert_dir, exist_ok=True)

key = ec.generate_private_key(ec.SECP256R1())
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
now = datetime.datetime.now(datetime.timezone.utc)
alt_names = x509.SubjectAlternativeName([
    x509.DNSName("localhost"),
    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
])

cert = (
    x509.CertificateBuilder()
    .subject_name(name)
    .issuer_name(name)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(alt_names, critical=False)
    .sign(key, hashes.SHA256())
)

key_pem = key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
cert_pem = cert.public_bytes(serialization.Encoding.PEM)

key_path = os.path.join(cert_dir, "key.pem")
cert_path = os.path.join(cert_dir, "cert.pem")

with open(key_path, "wb") as file:
    file.write(key_pem)

with open(cert_path, "wb") as file:
    file.write(cert_pem)

print(f"Created {cert_path} and {key_path}")
