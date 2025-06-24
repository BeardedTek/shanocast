# Shanocast Dynamic Certificate Generation Patch

This patch replaces Shanocast's precomputed signature approach with dynamic certificate generation using the AirReceiver private key method.

## Overview

The original Shanocast uses hardcoded certificates and precomputed signatures from AirReceiver. This patch implements dynamic certificate generation that:

1. **Loads the AirReceiver private key** from a PEM file
2. **Generates certificates on-the-fly** for each authentication challenge
3. **Signs challenges dynamically** using the private key
4. **Supports custom device IP addresses** for certificate generation

## Benefits

- **No date limitations**: Unlike precomputed signatures that expire, dynamic generation works indefinitely
- **Flexible device configuration**: Can specify custom IP addresses and device IDs
- **Real-time certificate generation**: Creates fresh certificates for each session
- **Uses actual AirReceiver key**: Leverages the same private key used by AirReceiver app

## Requirements

- OpenSSL development libraries
- AirReceiver private key file (`airreceiver_key.pem`)
- C++11 compatible compiler

## Installation

1. **Extract the AirReceiver private key** (if you haven't already):
   ```bash
   # From the cast_cert_generator directory
   cp airreceiver_key_fixed.pem /path/to/shanocast/airreceiver_key.pem
   ```

2. **Apply the patch** to Openscreen:
   ```bash
   cd /path/to/openscreen
   patch -p1 < /path/to/shanocast/shanocast_dynamic_cert_patch.patch
   ```

3. **Build Openscreen** with the patch applied

## Usage

### Basic Usage
```bash
# Run with default settings (192.168.1.100)
nix run .#shanocast lo
```

### Custom Configuration
The patch supports custom initialization through environment variables:

```bash
# Set custom key path and device IP
export SHANOCAST_KEY_PATH="/path/to/airreceiver_key.pem"
export SHANOCAST_DEVICE_IP="192.168.3.101"
nix run .#shanocast lo
```

## How It Works

### Certificate Generation
1. **Root CA Certificate**: Created using the AirReceiver private key
   - Valid for 10 years
   - Self-signed
   - Includes proper CA extensions

2. **Device Certificate**: Created for each device
   - Valid for 1 year
   - Signed by the root CA
   - Includes device-specific subject alternative names
   - Uses device IP address in SAN

3. **Dynamic Signing**: Each authentication challenge is signed using the private key
   - Uses SHA-256 for hashing
   - RSA-PSS or RSA-PKCS1v1.5 signing
   - No precomputed signatures needed

### Authentication Flow
1. Chrome sends `AuthChallenge` with random data
2. Shanocast generates device certificate using AirReceiver key
3. Shanocast signs the challenge data with the private key
4. Shanocast sends `AuthResponse` with certificate and signature
5. Chrome verifies the signature and certificate chain

## File Structure

```
shanocast/
├── shanocast_dynamic_cert_patch.patch  # Main patch file
├── DYNAMIC_CERT_README.md              # This file
├── airreceiver_key.pem                 # AirReceiver private key (user-provided)
└── shanocast.patch                     # Original precomputed signature patch
```

## Comparison with Original Approach

| Feature | Original Shanocast | Dynamic Certificate Patch |
|---------|-------------------|---------------------------|
| Signatures | Precomputed (date-limited) | Generated on-the-fly |
| Certificates | Hardcoded | Generated dynamically |
| Device IP | Fixed | Configurable |
| Expiration | Limited by precomputed data | Unlimited |
| Flexibility | Low | High |
| Maintenance | Requires signature updates | Self-maintaining |

## Troubleshooting

### Common Issues

1. **"Certificate generator not initialized"**
   - Ensure `airreceiver_key.pem` exists in the working directory
   - Check file permissions (should be readable)

2. **"Failed to load private key"**
   - Verify the key file is valid PEM format
   - Check OpenSSL installation

3. **Authentication failures**
   - Ensure device IP matches network configuration
   - Check certificate validity periods

### Debug Mode
Enable debug logging by setting:
```bash
export SHANOCAST_DEBUG=1
```

## Security Considerations

- **Private Key Protection**: Keep the AirReceiver private key secure
- **Certificate Validity**: Generated certificates have appropriate validity periods
- **Network Security**: Use on trusted networks only
- **Key Rotation**: Consider rotating the private key periodically

## Contributing

To modify the certificate generation:

1. Edit the `DynamicCertGenerator` class in the patch
2. Modify certificate extensions, validity periods, or signing algorithms
3. Rebuild and test with Chrome

## License

This patch follows the same license as the original Shanocast project. 