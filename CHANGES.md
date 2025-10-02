# Certificate Expiry Date Fix - Summary of Changes

## Overview

Fixed incorrect certificate expiry date calculations and created migration tools to correct existing DomainCertificate CRDs.

## Changes Made

### 1. Fixed Expiry Date Calculation in `unified_worker.py`

**Old (Incorrect) Code:**
```python
not_after = datetime(now.year + (1 if now.month <= 9 else 0), 
                     ((now.month + 3 - 1) % 12) + 1, 
                     min(now.day, 28)).strftime('%Y-%m-%dT%H:%M:%SZ')
```

**New (Correct) Code:**
```python
not_after = (now + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
```

### 2. Added Kubernetes TLS Secret Creation

Added functionality to automatically create/update Kubernetes secrets of type `kubernetes.io/tls` when certificates are issued:

- **Secret Name Format:** `tls-{domain-with-dashes}` (e.g., `tls-example-com`)
- **Secret Type:** `kubernetes.io/tls`
- **Secret Data:**
  - `tls.crt`: Base64-encoded certificate
  - `tls.key`: Base64-encoded private key
- **Location:** Same namespace as the DomainCertificate CRD

### 3. Added Migration Functions

#### In `unified_worker.py`:

**New Functions:**
- `parse_certificate_expiry_from_s3(domain, s3_bucket)` - Parses actual certificates from S3 to extract real expiry dates
- `migrate_certificate_expiry_dates()` - Runs on worker startup to fix all incorrect expiry dates

**New Import:**
```python
from cryptography import x509
from cryptography.hazmat.backends import default_backend
```

**Startup Behavior:**
The worker now runs the migration automatically on startup before processing any certificate requests.

### 4. Created Standalone Migration Script

**File:** `migrate_cert_expiry_dates.py`

A standalone script that can be run independently to fix certificate expiry dates.

**Features:**
- Dry-run mode (`--dry-run`)
- Process all certificates or specific ones (`--namespace`, `--name`)
- Reads actual certificate expiry dates from S3
- Updates DomainCertificate CRD status with correct dates
- Detailed logging and summary report

**Usage:**
```bash
# Dry run to see what would change
python migrate_cert_expiry_dates.py --dry-run

# Update all certificates
python migrate_cert_expiry_dates.py

# Update a specific certificate
python migrate_cert_expiry_dates.py --namespace default --name example-com
```

### 5. Documentation

**Created Files:**
- `MIGRATION.md` - Comprehensive migration guide
- `CHANGES.md` - This summary document

## Migration Process

### Automatic Migration (Recommended)

1. Deploy the updated `unified_worker.py`
2. Worker automatically runs migration on startup
3. Review logs for migration results
4. Verify updated expiry dates

### Manual Migration (If Needed)

1. Run the migration script in dry-run mode:
   ```bash
   python migrate_cert_expiry_dates.py --dry-run
   ```

2. Review the output to see what will be changed

3. Run the actual migration:
   ```bash
   python migrate_cert_expiry_dates.py
   ```

4. Check the summary for any failures

## What Gets Migrated

The migration will:
- ✅ Process all DomainCertificates in all namespaces
- ✅ Only update certificates in "Issued" or "Deployed" state
- ✅ Download certificate from S3
- ✅ Parse actual expiry date using cryptography library
- ✅ Update CRD status with correct `notBefore`, `notAfter`, and `serialNumber`
- ✅ Skip certificates that are already correct
- ✅ Log all actions and provide summary

## What Gets Skipped

Certificates are skipped if:
- ❌ No domain specified in spec
- ❌ Certificate state is not "Issued" or "Deployed"
- ❌ Certificate file not found in S3
- ❌ Expiry date is already correct
- ❌ Unable to parse certificate from S3

## Verification

After migration, verify the changes:

```bash
# List all certificates with their expiry dates
kubectl get domaincertificates -A -o custom-columns=\
NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
DOMAIN:.spec.domain,\
STATE:.status.state,\
NOT_AFTER:.status.notAfter

# Check a specific certificate in S3
aws s3 cp s3://your-bucket/certs/example.com/example.com.crt - | \
openssl x509 -noout -dates

# Check the Kubernetes TLS secret
kubectl get secret tls-example-com -n default -o yaml
```

## Rollback Plan

If issues occur:

1. Stop the worker: `kubectl scale deployment nginx-cert-manager-worker --replicas=0`
2. Restore previous version: `kubectl rollout undo deployment/nginx-cert-manager-worker`
3. Manually fix any affected certificates if needed

The migration is idempotent, so re-running it is safe.

## Dependencies

The migration requires these Python packages (already in `requirements.txt`):
- `cryptography>=44.0.2` - For X.509 certificate parsing
- `boto3` - For S3 access
- `kubernetes>=32.0.1` - For K8s API access
- `python-dotenv` - For environment configuration

## Permissions Required

The worker/migration script needs these Kubernetes permissions:
- `namespaces`: list, get
- `domaincertificates.cert.nginx.io`: list, get, patch (status subresource)
- `secrets`: create, get, update (for TLS secrets)

And these AWS permissions:
- S3: `s3:GetObject` on the certificate bucket

## Testing

1. Test the import:
   ```bash
   python -c "import unified_worker; print('OK')"
   python -c "import migrate_cert_expiry_dates; print('OK')"
   ```

2. Test dry-run migration:
   ```bash
   python migrate_cert_expiry_dates.py --dry-run
   ```

3. Deploy to a test environment first

4. Verify a few certificates manually

5. Deploy to production

## Monitoring

After deployment, monitor:
- Worker startup logs for migration results
- DomainCertificate status fields for correct dates
- TLS secrets creation
- Any error logs related to certificate parsing or S3 access

## Support

For issues:
1. Check worker logs for migration errors
2. Verify S3 access and certificate files exist
3. Check Kubernetes permissions
4. Run migration script manually with verbose logging
5. Contact the team with specific certificate names and error messages
