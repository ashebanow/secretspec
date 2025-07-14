---
title: CLI Commands Reference
description: Complete reference for SecretSpec CLI commands
---

The SecretSpec CLI provides commands for managing secrets across different providers and profiles.

## Commands

### init
Initialize a new `secretspec.toml` configuration file from an existing .env file.

```bash
secretspec init [OPTIONS]
```

**Options:**
- `-f, --from <PATH>` - Path to .env file to import from (default: `.env`)

**Example:**
```bash
$ secretspec init --from .env.example
✓ Created secretspec.toml with 5 secrets
```

### config init
Initialize user configuration interactively.

```bash
secretspec config init
```

**Example:**
```bash
$ secretspec config init
? Select your preferred provider backend:
> keyring: System keychain
? Select your default profile:
> development
✓ Configuration saved to ~/.config/secretspec/config.toml
```

### config show
Display current configuration.

```bash
secretspec config show
```

**Example:**
```bash
$ secretspec config show
Provider: keyring
Profile:  development
```

### check
Check if all required secrets are available, with interactive prompting for missing secrets.

```bash
secretspec check [OPTIONS]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec check --profile production
✓ DATABASE_URL - Database connection string
✗ API_KEY - API key for external service (required)
Enter value for API_KEY (profile: production): ****
✓ Secret 'API_KEY' saved to keyring (profile: production)
```

### get
Get a secret value.

```bash
secretspec get [OPTIONS] <NAME>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec get DATABASE_URL --profile production
postgresql://prod.example.com/mydb
```

### set
Set a secret value.

```bash
secretspec set [OPTIONS] <NAME> [VALUE]
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec set API_KEY sk-1234567890
✓ Secret 'API_KEY' saved to keyring (profile: development)
```

### run
Run a command with secrets injected as environment variables.

```bash
secretspec run [OPTIONS] -- <COMMAND>
```

**Options:**
- `-p, --provider <PROVIDER>` - Provider backend to use
- `-P, --profile <PROFILE>` - Profile to use

**Example:**
```bash
$ secretspec run --profile production -- npm run deploy
```

### import
Import secrets from one provider to another.

```bash
secretspec import <FROM_PROVIDER>
```

The destination provider and profile are determined from your configuration. Secrets that already exist in the destination provider will not be overwritten.

**Arguments:**
- `<FROM_PROVIDER>` - Provider to import from (e.g., `env`, `dotenv:/path/to/.env`)

**Example:**
```bash
# Import from environment variables to your default provider
$ secretspec import env
Importing secrets from env to keyring (profile: development)...

✓ DATABASE_URL - Database connection string
○ API_KEY - API key for external service (already exists in target)
✗ REDIS_URL - Redis connection URL (not found in source)

Summary: 1 imported, 1 already exists, 1 not found in source

# Import from a specific .env file
$ secretspec import dotenv:/home/user/old-project/.env
```

**Use Cases:**
- Migrate from .env files to a secure provider like keyring or OnePassword
- Copy secrets between different profiles or projects
- Import existing environment variables into SecretSpec management

## Environment Variables

| Variable | Description |
|----------|-------------|
| `SECRETSPEC_PROFILE` | Default profile to use |
| `SECRETSPEC_PROVIDER` | Default provider to use |

## Quick Start Workflow

```bash
# Initialize from existing .env
$ secretspec init --from .env

# Set up user configuration
$ secretspec config init

# Import existing secrets (optional)
$ secretspec import env  # or: secretspec import dotenv:.env.old

# Check and set missing secrets
$ secretspec check

# Run your application
$ secretspec run -- npm start
```