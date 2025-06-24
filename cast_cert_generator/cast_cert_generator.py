#!/usr/bin/env python3
"""
Cast Certificate Generator using AirReceiver Private Key
=======================================================

This script generates Cast certificates using the RSA private key extracted
from libAirReceiver.so. This allows us to create working certificates for
Cast authentication.

The AirReceiver app uses this private key to sign device and session certificates,
enabling it to authenticate with Google Cast devices.
"""

import os
import sys
import time
import hashlib
import base64
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import ipaddress
import argparse

class CastCertificateGenerator:
    def __init__(self, private_key_path="airreceiver_key_fixed.pem", device_ip="192.168.1.100"):
        """Initialize with the AirReceiver private key and device IP address."""
        self.private_key = self.load_private_key(private_key_path)
        self.device_id = self.generate_device_id()
        self.device_ip = device_ip
        
    def load_private_key(self, key_path):
        """Load the RSA private key from file."""
        try:
            with open(key_path, 'rb') as f:
                key_data = f.read()
            return load_pem_private_key(key_data, password=None)
        except Exception as e:
            print(f"Error loading private key: {e}")
            sys.exit(1)
    
    def generate_device_id(self):
        """Generate a unique device ID based on the private key."""
        # Use the public key modulus as device ID
        public_key = self.private_key.public_key()
        modulus = public_key.public_numbers().n
        device_id = hashlib.sha256(str(modulus).encode()).hexdigest()[:16]
        return device_id
    
    def create_root_ca_certificate(self):
        """Create a root CA certificate signed by the AirReceiver private key."""
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Google Cast Root CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cast Security"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            self.private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365*10)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).sign(self.private_key, hashes.SHA256())
        
        return cert
    
    def create_device_certificate(self, root_ca_cert):
        """Create a device certificate signed by the root CA."""
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Cast Device {self.device_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cast Device"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        # Generate device-specific key pair
        device_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            root_ca_cert.subject
        ).public_key(
            device_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)  # 1 year
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"cast-{self.device_id}.local"),
                x509.IPAddress(ipaddress.IPv4Address(self.device_ip))
            ]),
            critical=False
        ).sign(self.private_key, hashes.SHA256())
        
        return cert, device_key
    
    def create_session_certificate(self, device_cert, device_key):
        """Create a session certificate for a specific Cast session."""
        session_id = hashlib.sha256(str(time.time()).encode()).hexdigest()[:8]
        
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"Cast Session {session_id}"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Google Inc."),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Cast Session"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ])
        
        # Generate session-specific key pair
        session_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            device_cert.subject
        ).public_key(
            session_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(hours=24)  # 24 hours
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"session-{session_id}.cast.local"),
            ]),
            critical=False
        ).sign(device_key, hashes.SHA256())
        
        return cert, session_key, session_id
    
    def save_certificate_chain(self, root_cert, device_cert, session_cert, 
                              device_key, session_key, session_id):
        """Save the certificate chain and keys to files."""
        # Save certificates
        with open(f"cast_root_ca.pem", "wb") as f:
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(f"cast_device_cert.pem", "wb") as f:
            f.write(device_cert.public_bytes(serialization.Encoding.PEM))
        
        with open(f"cast_session_{session_id}_cert.pem", "wb") as f:
            f.write(session_cert.public_bytes(serialization.Encoding.PEM))
        
        # Save private keys
        with open(f"cast_device_key.pem", "wb") as f:
            f.write(device_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(f"cast_session_{session_id}_key.pem", "wb") as f:
            f.write(session_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save certificate chain
        with open(f"cast_cert_chain_{session_id}.pem", "wb") as f:
            f.write(session_cert.public_bytes(serialization.Encoding.PEM))
            f.write(device_cert.public_bytes(serialization.Encoding.PEM))
            f.write(root_cert.public_bytes(serialization.Encoding.PEM))
        
        print(f"Certificate chain saved for session {session_id}")
        print(f"Files created:")
        print(f"  - cast_root_ca.pem")
        print(f"  - cast_device_cert.pem")
        print(f"  - cast_device_key.pem")
        print(f"  - cast_session_{session_id}_cert.pem")
        print(f"  - cast_session_{session_id}_key.pem")
        print(f"  - cast_cert_chain_{session_id}.pem")
    
    def generate_cast_certificates(self):
        """Generate the complete Cast certificate chain."""
        print("Generating Cast certificate chain using AirReceiver private key...")
        print(f"Device ID: {self.device_id}")
        
        # Create root CA certificate
        print("Creating root CA certificate...")
        root_cert = self.create_root_ca_certificate()
        
        # Create device certificate
        print("Creating device certificate...")
        device_cert, device_key = self.create_device_certificate(root_cert)
        
        # Create session certificate
        print("Creating session certificate...")
        session_cert, session_key, session_id = self.create_session_certificate(device_cert, device_key)
        
        # Save everything
        self.save_certificate_chain(root_cert, device_cert, session_cert, 
                                  device_key, session_key, session_id)
        
        print("\nCast certificate generation complete!")
        print("These certificates can be used for Cast authentication.")
        print("Note: This uses the actual private key from AirReceiver, so it should work!")

def main():
    """Main function to generate Cast certificates."""
    parser = argparse.ArgumentParser(description="Generate Cast certificates using AirReceiver private key.")
    parser.add_argument('device_ip', nargs='?', default='192.168.1.100', help='Device IP address for certificate (default: 192.168.1.100)')
    args = parser.parse_args()

    if not os.path.exists("airreceiver_key_fixed.pem"):
        print("Error: airreceiver_key_fixed.pem not found!")
        print("Make sure you have extracted the private key from libAirReceiver.so")
        sys.exit(1)
    
    generator = CastCertificateGenerator(device_ip=args.device_ip)
    generator.generate_cast_certificates()

if __name__ == "__main__":
    main() 