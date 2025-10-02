# Certificate Expiry Date Migration

## Problem

The certificate expiry dates in the `DomainCertificate` CRDs were calculated incorrectly using a flawed date arithmetic formula. The incorrect formula was:

```python
not_after = datetime(now.year + (1 if now.month <= 9 else 0), 
                     ((now.month + 3 - 1) % 12) + 1, 
                     min(now.day, 28)).strftime('%Y-%m-%dT%H:%M:%SZ')
```

This resulted in past or incorrect expiry dates for certificates.

## Solution

The fix uses the correct calculation:

```python
not_after = (now + timedelta(days=90)).strftime('%Y-%m-%dT%H:%M:%SZ')
```

## Migration

To correct the expiry dates for existing certificates, we need to:

1. Read the actual certificates from S3
2. Parse the certificates to extract the real expiry dates
3. Update the CRD status with the correct dates

### Automatic Migration on Startup

The `unified_worker.py` now automatically runs a migration on startup to fix all incorrect expiry dates. This happens before the worker starts processing certificate requests.

The migration will:
- Check all DomainCertificates across all namespaces
- For certificates in "Issued" or "Deployed" state:
  - Download the certificate from S3
  - Parse the actual expiry date
  - Update the CRD status if the date is incorrect
- Log a summary of successful updates, failures, and skipped certificates

### Manual Migration Script

For manual migration or troubleshooting, use the `migrate_cert_expiry_dates.py` script:

#### Run Migration in Dry-Run Mode

To see what would be changed without making actual updates:

```bash
python migrate_cert_expiry_dates.py --dry-run
```

#### Run Full Migration

To update all certificates:

```bash
python migrate_cert_expiry_dates.py
```

#### Migrate a Single Certificate

To update a specific certificate:

```bash
python migrate_cert_expiry_dates.py --namespace default --name my-domain-com
```

### Migration Output

The migration will log:
- Each certificate being processed
- The old and new expiry dates
- A summary with counts of:
  - Successfully updated certificates
  - Failed updates
  - Skipped certificates (no S3 cert, already correct, wrong state, etc.)

Example output:

```
================================================================================
Starting certificate expiry date migration on startup
================================================================================
Found 5 namespaces to check
Checking 3 DomainCertificates in namespace default
Updating default/example-com: 2025-09-15T10:30:00Z -> 2026-01-05T14:22:15Z
Successfully updated default/example-com
Updating default/test-example-com: 2025-08-20T08:15:00Z -> 2026-01-10T12:45:30Z
Successfully updated default/test-example-com
Skipping default/pending-cert: state is Processing
================================================================================
Certificate expiry date migration summary:
  Successfully updated: 2
  Failed: 0
  Skipped: 1
================================================================================
```

### Requirements

The migration requires:
- Access to S3 bucket with certificates (`S3_CERT_BUCKET` environment variable)
- Kubernetes access with permissions to:
  - List namespaces
  - List DomainCertificates in all namespaces
  - Patch DomainCertificate status
- Python packages:
  - `cryptography` - for parsing X.509 certificates
  - `boto3` - for S3 access
  - `kubernetes` - for K8s API access

### Skipped Certificates

Certificates are skipped if:
- No domain specified in the spec
- Certificate state is not "Issued" or "Deployed"
- Certificate file not found in S3
- Expiry date is already correct
- Unable to parse certificate from S3

### Error Handling

If the migration fails for individual certificates, it will:
- Log the error
- Continue processing other certificates
- Report the failure count in the summary

The worker will continue starting even if the migration encounters errors, but failed certificates should be investigated and migrated manually.

### Verification

After migration, verify the updated expiry dates:

```bash
kubectl get domaincertificates -A -o custom-columns=\
NAMESPACE:.metadata.namespace,\
NAME:.metadata.name,\
DOMAIN:.spec.domain,\
STATE:.status.state,\
NOT_AFTER:.status.notAfter
```

Compare the `notAfter` dates with the actual certificates in S3 or check with:

```bash
# For a specific domain
aws s3 cp s3://your-bucket/certs/example.com/example.com.crt - | \
openssl x509 -noout -enddate
```

## Future Prevention

Going forward, the worker will:
1. Always calculate expiry dates correctly using `timedelta(days=90)`
2. Ideally, parse actual certificate files to get real expiry dates instead of calculating them
3. Run the migration check on startup to catch any future issues

## Rollback

If the migration causes issues, you can:
1. Stop the worker
2. Restore CRD status from a backup (if available)
3. Fix the migration script and re-run

The migration is idempotent - running it multiple times is safe as it only updates certificates with incorrect dates.
