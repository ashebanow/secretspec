---
title: Bitwarden Provider
description: Bitwarden & BWS secrets management integration
---

The Bitwarden provider integrates with both Bitwarden Password Manager and Bitwarden Secrets Manager (BWS) for comprehensive secret management with vault-wide access to all item types.

## Prerequisites

### Password Manager
- Bitwarden CLI (`bw`)
- Bitwarden account
- Signed in via `bw login` and unlocked with `bw unlock`
- `BW_SESSION` environment variable set

### Secrets Manager  
- Bitwarden Secrets Manager CLI (`bws`)
- BWS machine account access token
- `BWS_ACCESS_TOKEN` environment variable set

## Configuration

### URI Format

#### Password Manager URIs
```
bitwarden://[collection-id]
bitwarden://[org@collection]
bitwarden://?server=https://vault.company.com
bitwarden://?type=login&field=password
```

#### Secrets Manager URIs
```
bws://[project-id]
bws://?project=project-id
```

- `collection-id`: Target collection ID
- `org@collection`: Organization and collection specification
- `project-id`: BWS project ID
- `type`: Item type (login, card, identity, sshkey, securenote)
- `field`: Specific field to extract

### Examples

```bash
# Password Manager - Personal vault
$ secretspec set API_KEY --provider bitwarden://

# Password Manager - Organization collection
$ secretspec set DATABASE_URL --provider "bitwarden://myorg@dev-secrets"

# Password Manager - Self-hosted instance
$ secretspec set TOKEN --provider "bitwarden://?server=https://vault.company.com"

# Password Manager - Specific item type and field
$ secretspec get 'MyApp Database' --provider 'bitwarden://?type=login&field=username'

# Secrets Manager - Default project
$ secretspec set API_KEY --provider bws://

# Secrets Manager - Specific project  
$ secretspec set DATABASE_URL --provider bws://be8e0ad8-d545-4017-a55a-b02f014d4158
```

## Usage

### Basic Commands

```bash
# Set a secret (Password Manager)
$ secretspec set DATABASE_URL
Enter value for DATABASE_URL: postgresql://localhost/mydb
✓ Secret DATABASE_URL saved to Bitwarden

# Get a secret from existing vault item
$ secretspec get 'MyApp Database' --provider 'bitwarden://?type=login'

# Run with secrets
$ secretspec run -- npm start
```

### Item Type Configuration

The Bitwarden provider supports all Bitwarden item types with smart field detection:

#### Login Items (Default)
```bash
# Get password field (default)
$ secretspec get 'Database Login' --provider 'bitwarden://?type=login'

# Get username field
$ secretspec get 'Database Login' --provider 'bitwarden://?type=login&field=username'

# Get custom field
$ secretspec get 'API Service' --provider 'bitwarden://?type=login&field=api_key'
```

#### Credit Card Items
```bash
# Get API key from custom field (field required)
$ secretspec get 'Stripe Payment' --provider 'bitwarden://?type=card&field=api_key'

# Get card number
$ secretspec get 'Company Card' --provider 'bitwarden://?type=card&field=number'
```

#### SSH Key Items
```bash
# Get private key (default)
$ secretspec get 'Deploy Key' --provider 'bitwarden://?type=sshkey'

# Get passphrase
$ secretspec get 'Deploy Key' --provider 'bitwarden://?type=sshkey&field=passphrase'
```

#### Identity Items
```bash
# Get custom field (field required)
$ secretspec get 'Employee Record' --provider 'bitwarden://?type=identity&field=employee_id'

# Get email field
$ secretspec get 'Personal Identity' --provider 'bitwarden://?type=identity&field=email'
```

#### Secure Note Items
```bash
# Get value from secure note
$ secretspec get 'Legacy Config' --provider 'bitwarden://?type=securenote&field=config_value'
```

### Profile Configuration

```toml
# secretspec.toml
[development]
provider = "bitwarden://dev-secrets"

[production]  
provider = "bitwarden://prod-secrets"

# BWS Configuration
[staging]
provider = "bws://staging-project-id"
```

### Environment Variables

#### Authentication
```bash
# Password Manager session
$ export BW_SESSION="your-session-key"

# Secrets Manager access token
$ export BWS_ACCESS_TOKEN="your-access-token"
```

#### Configuration Defaults
```bash
# Set item type and field defaults
$ export BITWARDEN_DEFAULT_TYPE=login
$ export BITWARDEN_DEFAULT_FIELD=password

# Organization settings
$ export BITWARDEN_ORGANIZATION=myorg
$ export BITWARDEN_COLLECTION=dev-secrets

# Use defaults
$ secretspec get DATABASE_PASSWORD --provider bitwarden://
```

### CI/CD Integration

#### Password Manager with Session Key
```bash
# Login and unlock (interactive)
$ bw login
$ bw unlock

# Export session for automation
$ export BW_SESSION="session-key-from-unlock"

# Use in CI/CD
$ secretspec run --provider bitwarden://Production -- deploy
```

#### Secrets Manager with Access Token
```bash
# Set access token
$ export BWS_ACCESS_TOKEN="your-machine-account-token"

# Use in automation
$ secretspec run --provider bws://prod-project-id -- deploy
```

## Field Requirements by Item Type

| Item Type    | Default Field  | Field Required? | Notes                    |
|--------------|----------------|-----------------|--------------------------|
| Login        | `password`     | No              | Falls back to username   |
| SSH Key      | `private_key`  | No              | Standard SSH key field   |
| Card         | None           | **YES**         | Must specify field       |
| Identity     | None           | **YES**         | Must specify field       |
| Secure Note  | Smart detect   | No              | Uses note content/fields |

## Error Handling

The provider includes comprehensive error handling with helpful guidance:

### CLI Installation
```
Bitwarden CLI (bw) is not installed.

To install it:
  - npm: npm install -g @bitwarden/cli
  - Homebrew: brew install bitwarden-cli
  - Download: https://bitwarden.com/help/cli/
```

### Authentication Issues
- Clear distinction between "not logged in" vs "vault locked"
- Step-by-step guidance for `bw login` and `bw unlock`
- Session key setup instructions
- BWS access token configuration help

### Item Access
- Graceful handling of missing items
- Field validation and suggestions
- Organization/collection permission guidance