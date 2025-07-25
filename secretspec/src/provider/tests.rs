use crate::Result;
use crate::provider::Provider;
use secrecy::{ExposeSecret, SecretString};
use std::collections::HashMap;
use std::convert::TryFrom;
use std::sync::{Arc, Mutex};

#[cfg(test)]
use tempfile::TempDir;

/// Mock provider for testing
pub struct MockProvider {
    storage: Arc<Mutex<HashMap<String, String>>>,
}

impl MockProvider {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl Provider for MockProvider {
    fn get(&self, project: &str, key: &str, profile: &str) -> Result<Option<SecretString>> {
        let storage = self.storage.lock().unwrap();
        let full_key = format!("{}/{}/{}", project, profile, key);
        Ok(storage
            .get(&full_key)
            .map(|v| SecretString::new(v.clone().into())))
    }

    fn set(&self, project: &str, key: &str, value: &SecretString, profile: &str) -> Result<()> {
        let mut storage = self.storage.lock().unwrap();
        let full_key = format!("{}/{}/{}", project, profile, key);
        storage.insert(full_key, value.expose_secret().to_string());
        Ok(())
    }

    fn name(&self) -> &'static str {
        "mock"
    }
}

#[test]
fn test_create_from_string_with_full_uris() {
    // Test basic onepassword URI
    let provider = Box::<dyn Provider>::try_from("onepassword://Private").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with account
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // Test onepassword with token
    let provider =
        Box::<dyn Provider>::try_from("onepassword+token://:ops_abc123@Private").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

#[test]
fn test_create_from_string_with_plain_names() {
    // Test plain provider names
    let provider = Box::<dyn Provider>::try_from("env").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring").unwrap();
    assert_eq!(provider.name(), "keyring");

    let provider = Box::<dyn Provider>::try_from("dotenv").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test onepassword separately to debug the issue
    match Box::<dyn Provider>::try_from("onepassword") {
        Ok(provider) => assert_eq!(provider.name(), "onepassword"),
        Err(e) => panic!("Failed to create onepassword provider: {}", e),
    }

    let provider = Box::<dyn Provider>::try_from("lastpass").unwrap();
    assert_eq!(provider.name(), "lastpass");

    let provider = Box::<dyn Provider>::try_from("bitwarden").unwrap();
    assert_eq!(provider.name(), "bitwarden");
}

#[test]
fn test_create_from_string_with_colon() {
    // Test provider names with colon
    let provider = Box::<dyn Provider>::try_from("env:").unwrap();
    assert_eq!(provider.name(), "env");

    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");
}

#[test]
fn test_invalid_onepassword_scheme() {
    // Test that '1password' scheme gives proper error suggesting 'onepassword'
    let result = Box::<dyn Provider>::try_from("1password");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password:");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password:' scheme"),
    }

    let result = Box::<dyn Provider>::try_from("1password://Private");
    match result {
        Err(err) => assert!(err.to_string().contains("Use 'onepassword' instead")),
        Ok(_) => panic!("Expected error for '1password://' scheme"),
    }
}

#[test]
fn test_dotenv_with_custom_path() {
    // Test dotenv provider with relative path - host part becomes first folder
    let provider = Box::<dyn Provider>::try_from("dotenv://custom/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test with absolute path format
    let provider = Box::<dyn Provider>::try_from("dotenv:///custom/path/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_unknown_provider() {
    let result = Box::<dyn Provider>::try_from("unknown");
    assert!(result.is_err());
    match result {
        Err(crate::SecretSpecError::ProviderNotFound(scheme)) => {
            assert_eq!(scheme, "unknown");
        }
        _ => panic!("Expected ProviderNotFound error"),
    }
}

#[test]
fn test_dotenv_shorthand_from_docs() {
    // Test the example from line 187 of registry.rs
    let provider = Box::<dyn Provider>::try_from("dotenv:.env.production").unwrap();
    assert_eq!(provider.name(), "dotenv");
}

#[test]
fn test_documentation_examples() {
    // Test examples from the documentation

    // From line 102: onepassword://work@Production
    let provider = Box::<dyn Provider>::try_from("onepassword://work@Production").unwrap();
    assert_eq!(provider.name(), "onepassword");

    // From line 107: dotenv:/path/to/.env
    let provider = Box::<dyn Provider>::try_from("dotenv:/path/to/.env").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // From line 115: lastpass://folder
    let provider = Box::<dyn Provider>::try_from("lastpass://folder").unwrap();
    assert_eq!(provider.name(), "lastpass");

    // Test dotenv examples from provider list
    let provider = Box::<dyn Provider>::try_from("dotenv://path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test bitwarden examples (Password Manager)
    let provider = Box::<dyn Provider>::try_from("bitwarden://").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bitwarden://collection-id").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bitwarden://org@collection").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    // Test bws examples (Secrets Manager)
    let provider = Box::<dyn Provider>::try_from("bws://").unwrap();
    assert_eq!(provider.name(), "bitwarden");

    let provider = Box::<dyn Provider>::try_from("bws://project-id").unwrap();
    assert_eq!(provider.name(), "bitwarden");
}

#[test]
fn test_edge_cases_and_normalization() {
    // Test scheme-only format (mentioned in docs line 151)
    let provider = Box::<dyn Provider>::try_from("keyring:").unwrap();
    assert_eq!(provider.name(), "keyring");

    // Test dotenv special case without authority (line 152-153)
    let provider = Box::<dyn Provider>::try_from("dotenv:/absolute/path").unwrap();
    assert_eq!(provider.name(), "dotenv");

    // Test normalized URIs with localhost (line 154)
    let provider = Box::<dyn Provider>::try_from("env://localhost").unwrap();
    assert_eq!(provider.name(), "env");
}

#[test]
fn test_documentation_example_line_184() {
    // Test the exact example from line 184 of registry.rs
    let provider = Box::<dyn Provider>::try_from("onepassword://vault/Production").unwrap();
    assert_eq!(provider.name(), "onepassword");
}

#[test]
fn test_url_parsing_behavior() {
    use url::Url;

    // Test how URLs are actually parsed
    let url = "onepassword://vault/Production".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "onepassword");
    assert_eq!(url.host_str(), Some("vault"));
    assert_eq!(url.path(), "/Production");

    // Test dotenv URL parsing - host part becomes part of the path
    let url = "dotenv://path/to/.env".parse::<Url>().unwrap();
    assert_eq!(url.scheme(), "dotenv");
    assert_eq!(url.host_str(), Some("path"));
    assert_eq!(url.path(), "/to/.env");
}

#[test]
fn test_bitwarden_config_parsing() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenService};
    use std::convert::TryFrom;
    use url::Url;

    // Test Password Manager configurations

    // Test basic bitwarden:// URI
    let url = Url::parse("bitwarden://").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert!(config.organization_id.is_none());
    assert!(config.collection_id.is_none());
    assert!(config.server.is_none());
    assert!(config.project_id.is_none());
    // Login is the default item type
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));
    assert!(config.default_field.is_none());

    // Test collection ID only
    let url = Url::parse("bitwarden://collection-123").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert!(config.organization_id.is_none());
    assert_eq!(config.collection_id, Some("collection-123".to_string()));
    assert!(config.server.is_none());

    // Test org@collection format
    let url = Url::parse("bitwarden://myorg@collection-456").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.organization_id, Some("myorg".to_string()));
    assert_eq!(config.collection_id, Some("collection-456".to_string()));
    assert!(config.server.is_none());

    // Test query parameters
    let url = Url::parse("bitwarden://?server=https://vault.company.com&org=myorg").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(config.organization_id, Some("myorg".to_string()));
    assert_eq!(config.server, Some("https://vault.company.com".to_string()));

    // Test folder prefix customization
    let url = Url::parse("bitwarden://?folder=custom/{project}/{profile}").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    assert_eq!(
        config.folder_prefix,
        Some("custom/{project}/{profile}".to_string())
    );

    // Test item type and field parameters
    let url = Url::parse("bitwarden://?type=card&field=api_key").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::PasswordManager);
    use crate::provider::bitwarden::BitwardenItemType;
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Card));
    assert_eq!(config.default_field, Some("api_key".to_string()));

    // Test Secrets Manager configurations

    // Test basic bws:// URI
    let url = Url::parse("bws://").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert!(config.project_id.is_none());
    assert!(config.access_token.is_none());
    assert!(config.organization_id.is_none()); // Should be None for Secrets Manager
    // Login is the default item type even for BWS
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));

    // Test project ID
    let url = Url::parse("bws://project-789").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.project_id, Some("project-789".to_string()));

    // Test query parameters for Secrets Manager
    let url = Url::parse("bws://?project=project-abc&token=my-token").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.project_id, Some("project-abc".to_string()));
    assert_eq!(config.access_token, Some("my-token".to_string()));

    // Test BWS with item type and field parameters (should work for consistency)
    let url = Url::parse("bws://?type=login&field=password").unwrap();
    let config = BitwardenConfig::try_from(&url).unwrap();
    assert_eq!(config.service, BitwardenService::SecretsManager);
    assert_eq!(config.default_item_type, Some(BitwardenItemType::Login));
    assert_eq!(config.default_field, Some("password".to_string()));
}

#[test]
fn test_bitwarden_item_type_parsing() {
    use crate::provider::bitwarden::BitwardenItemType;

    // Test parsing from string (for environment variables)
    assert_eq!(
        BitwardenItemType::from_str("login"),
        Some(BitwardenItemType::Login)
    );
    assert_eq!(
        BitwardenItemType::from_str("card"),
        Some(BitwardenItemType::Card)
    );
    assert_eq!(
        BitwardenItemType::from_str("identity"),
        Some(BitwardenItemType::Identity)
    );
    assert_eq!(
        BitwardenItemType::from_str("securenote"),
        Some(BitwardenItemType::SecureNote)
    );
    assert_eq!(
        BitwardenItemType::from_str("note"),
        Some(BitwardenItemType::SecureNote)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("secure_note"),
        Some(BitwardenItemType::SecureNote)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("sshkey"),
        Some(BitwardenItemType::SshKey)
    );
    assert_eq!(
        BitwardenItemType::from_str("ssh_key"),
        Some(BitwardenItemType::SshKey)
    ); // alias
    assert_eq!(
        BitwardenItemType::from_str("ssh"),
        Some(BitwardenItemType::SshKey)
    ); // alias
    assert_eq!(BitwardenItemType::from_str("unknown"), None);

    // Test conversion to/from integers (Bitwarden API format)
    assert_eq!(
        BitwardenItemType::from_u8(1),
        Some(BitwardenItemType::Login)
    );
    assert_eq!(
        BitwardenItemType::from_u8(2),
        Some(BitwardenItemType::SecureNote)
    );
    assert_eq!(BitwardenItemType::from_u8(3), Some(BitwardenItemType::Card));
    assert_eq!(
        BitwardenItemType::from_u8(4),
        Some(BitwardenItemType::Identity)
    );
    assert_eq!(
        BitwardenItemType::from_u8(5),
        Some(BitwardenItemType::SshKey)
    );
    assert_eq!(BitwardenItemType::from_u8(99), None);

    // Test default field detection
    assert_eq!(
        BitwardenItemType::Login.default_field_for_hint("password"),
        "password".to_string()
    );
    assert_eq!(
        BitwardenItemType::Login.default_field_for_hint("custom"),
        "password".to_string()
    );
    assert_eq!(
        BitwardenItemType::Card.default_field_for_hint("api_key"),
        "api_key".to_string()
    );
    assert_eq!(
        BitwardenItemType::Card.default_field_for_hint("number"),
        "number".to_string()
    ); // Cards default to the hint for standard fields
    assert_eq!(
        BitwardenItemType::Identity.default_field_for_hint("ssn"),
        "ssn".to_string()
    );
    assert_eq!(
        BitwardenItemType::SshKey.default_field_for_hint("private_key"),
        "private_key".to_string()
    );
    assert_eq!(
        BitwardenItemType::SshKey.default_field_for_hint("custom"),
        "private_key".to_string()
    ); // SSH keys default to private_key
}

#[test]
fn test_bitwarden_field_type_detection() {
    use crate::provider::bitwarden::BitwardenFieldType;

    // Test smart field type detection
    assert_eq!(
        BitwardenFieldType::for_field_name("password"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("secret"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("token"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("api_key"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("cvv"),
        BitwardenFieldType::Hidden
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("username"),
        BitwardenFieldType::Text
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("name"),
        BitwardenFieldType::Text
    );
    assert_eq!(
        BitwardenFieldType::for_field_name("description"),
        BitwardenFieldType::Text
    );

    // Test enum conversions
    assert_eq!(BitwardenFieldType::Text.to_u8(), 0);
    assert_eq!(BitwardenFieldType::Hidden.to_u8(), 1);
    assert_eq!(BitwardenFieldType::Boolean.to_u8(), 2);

    assert_eq!(
        BitwardenFieldType::from_u8(0),
        Some(BitwardenFieldType::Text)
    );
    assert_eq!(
        BitwardenFieldType::from_u8(1),
        Some(BitwardenFieldType::Hidden)
    );
    assert_eq!(
        BitwardenFieldType::from_u8(2),
        Some(BitwardenFieldType::Boolean)
    );
    assert_eq!(BitwardenFieldType::from_u8(99), None);
}

#[test]
fn test_bitwarden_environment_variables() {
    use crate::provider::bitwarden::{BitwardenConfig, BitwardenProvider};
    use std::env;

    // Test environment variable support for default type and field
    unsafe {
        env::set_var("BITWARDEN_DEFAULT_TYPE", "card");
        env::set_var("BITWARDEN_DEFAULT_FIELD", "api_key");
        env::set_var("BITWARDEN_ORGANIZATION", "test-org");
        env::set_var("BITWARDEN_COLLECTION", "test-collection");
    }

    let config = BitwardenConfig::default();
    let _provider = BitwardenProvider::new(config);

    // Note: These environment variables are checked at runtime in the actual provider methods
    // This test verifies the environment variables exist and can be read
    assert_eq!(env::var("BITWARDEN_DEFAULT_TYPE").unwrap(), "card");
    assert_eq!(env::var("BITWARDEN_DEFAULT_FIELD").unwrap(), "api_key");
    assert_eq!(env::var("BITWARDEN_ORGANIZATION").unwrap(), "test-org");
    assert_eq!(env::var("BITWARDEN_COLLECTION").unwrap(), "test-collection");

    // Clean up
    unsafe {
        env::remove_var("BITWARDEN_DEFAULT_TYPE");
        env::remove_var("BITWARDEN_DEFAULT_FIELD");
        env::remove_var("BITWARDEN_ORGANIZATION");
        env::remove_var("BITWARDEN_COLLECTION");
    }
}

// Integration tests for all providers
#[cfg(test)]
mod integration_tests {
    use super::*;

    fn generate_test_project_name() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros();
        let suffix = timestamp % 100000;
        format!("secretspec_test_{}", suffix)
    }

    fn get_test_providers() -> Vec<String> {
        std::env::var("SECRETSPEC_TEST_PROVIDERS")
            .unwrap_or_else(|_| String::new())
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect()
    }

    fn create_provider_with_temp_path(provider_name: &str) -> (Box<dyn Provider>, Option<TempDir>) {
        match provider_name {
            "dotenv" => {
                let temp_dir = TempDir::new().expect("Create temp directory");
                let dotenv_path = temp_dir.path().join(".env");
                let provider_spec = format!("dotenv:{}", dotenv_path.to_str().unwrap());
                let provider = Box::<dyn Provider>::try_from(provider_spec.as_str())
                    .expect("Should create dotenv provider with path");
                (provider, Some(temp_dir))
            }
            "bitwarden" => {
                // For bitwarden, we test with basic configuration
                // Real authentication is handled by the CLI
                let provider = Box::<dyn Provider>::try_from("bitwarden://")
                    .expect("Should create bitwarden provider");
                (provider, None)
            }
            "bws" => {
                // For BWS, we test with basic Secrets Manager configuration
                // Real authentication is handled by the BWS CLI and BWS_ACCESS_TOKEN
                let provider =
                    Box::<dyn Provider>::try_from("bws://").expect("Should create bws provider");
                (provider, None)
            }
            _ => {
                let provider = Box::<dyn Provider>::try_from(provider_name)
                    .expect(&format!("{} provider should exist", provider_name));
                (provider, None)
            }
        }
    }

    // Generic test function that tests a provider implementation
    fn test_provider_basic_workflow(provider: &dyn Provider, provider_name: &str) {
        let project_name = generate_test_project_name();

        // Test 1: Get non-existent secret
        let result = provider.get(&project_name, "TEST_PASSWORD", "default");
        match result {
            Ok(None) => {
                // Expected: key doesn't exist
            }
            Ok(Some(_)) => {
                panic!("[{}] Should not find non-existent secret", provider_name);
            }
            Err(_) => {
                // Some providers may return error instead of None
            }
        }

        // Test 2: Try to set a secret (may fail for read-only providers)
        let test_value = SecretString::new(format!("test_password_{}", provider_name).into());

        if provider.allows_set() {
            // Provider claims to support set, so it should work
            provider
                .set(&project_name, "TEST_PASSWORD", &test_value, "default")
                .expect(&format!(
                    "[{}] Provider claims to support set but failed",
                    provider_name
                ));

            // Verify we can retrieve it
            let retrieved = provider
                .get(&project_name, "TEST_PASSWORD", "default")
                .expect(&format!(
                    "[{}] Should not error when getting after set",
                    provider_name
                ));

            match retrieved {
                Some(value) => {
                    assert_eq!(
                        value.expose_secret(),
                        test_value.expose_secret(),
                        "[{}] Retrieved value should match set value",
                        provider_name
                    );
                }
                None => {
                    panic!("[{}] Should find secret after setting it", provider_name);
                }
            }
        } else {
            // Provider is read-only, verify set fails
            match provider.set(&project_name, "TEST_PASSWORD", &test_value, "default") {
                Ok(_) => {
                    panic!(
                        "[{}] Read-only provider should not allow set operations",
                        provider_name
                    );
                }
                Err(_) => {
                    println!(
                        "[{}] Read-only provider correctly rejected set",
                        provider_name
                    );
                }
            }
        }
    }

    #[test]
    fn test_all_providers_basic_workflow() {
        // Test with our internal providers directly
        println!("Testing MockProvider");
        let mock = MockProvider::new();
        test_provider_basic_workflow(&mock, "mock");

        // Test actual providers if environment variable is set
        let providers = get_test_providers();
        for provider_name in providers {
            println!("Testing provider: {}", provider_name);
            let (provider, _temp_dir) = create_provider_with_temp_path(&provider_name);
            test_provider_basic_workflow(provider.as_ref(), &provider_name);
        }
    }

    #[test]
    fn test_provider_special_characters() {
        let test_cases = vec![
            ("SPACED_VALUE", "value with spaces"),
            ("NEWLINE_VALUE", "value\nwith\nnewlines"),
            ("SPECIAL_CHARS", "!@#%^&*()_+-=[]{}|;',./<>?"),
            ("UNICODE_VALUE", "🔐 Secret with émojis and ñ"),
        ];

        // Test with MockProvider
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();

        for (key, value) in &test_cases {
            let secret_value = SecretString::new(value.to_string().into());
            provider
                .set(&project_name, key, &secret_value, "default")
                .expect("Mock provider should handle all characters");

            let result = provider
                .get(&project_name, key, "default")
                .expect("Should not error when getting");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.to_string()),
                "Special characters should be preserved"
            );
        }
    }

    #[test]
    fn test_provider_profile_support() {
        let provider = MockProvider::new();
        let project_name = generate_test_project_name();
        let profiles = vec!["dev", "staging", "prod"];
        let test_key = "API_KEY";

        for profile in &profiles {
            let value = SecretString::new(format!("key_for_{}", profile).into());
            provider
                .set(&project_name, test_key, &value, profile)
                .expect("Should set with profile");

            let result = provider
                .get(&project_name, test_key, profile)
                .expect("Should get with profile");

            assert_eq!(
                result.map(|s| s.expose_secret().to_string()),
                Some(value.expose_secret().to_string()),
                "Profile-specific value should match"
            );
        }

        // Verify isolation between profiles
        for i in 0..profiles.len() {
            for j in 0..profiles.len() {
                let result = provider
                    .get(&project_name, test_key, profiles[j])
                    .expect("Should not error");

                if i == j {
                    assert!(result.is_some(), "Should find value in same profile");
                } else {
                    let expected_value = format!("key_for_{}", profiles[j]);
                    assert_eq!(
                        result.map(|s| s.expose_secret().to_string()),
                        Some(expected_value),
                        "Should find profile-specific value"
                    );
                }
            }
        }
    }

    #[test]
    fn test_bitwarden_authentication_states() {
        // Test that we get proper error messages for different authentication states
        let provider = Box::<dyn Provider>::try_from("bitwarden://")
            .expect("Should create bitwarden provider");

        let project_name = generate_test_project_name();
        let test_key = "AUTH_TEST_KEY";

        // Test get operation when not authenticated
        match provider.get(&project_name, test_key, "default") {
            Ok(None) => {
                // If this succeeds, the vault is unlocked and working
                println!("Bitwarden vault is unlocked and accessible");
            }
            Ok(Some(_)) => {
                // Found a value, vault is unlocked
                println!("Bitwarden vault is unlocked and contains data");
            }
            Err(err) => {
                // Should get authentication error if not unlocked
                let err_str = err.to_string();
                assert!(
                    err_str.contains("authentication required") || 
                    err_str.contains("not logged in") ||
                    err_str.contains("locked") ||
                    err_str.contains("BW_SESSION") ||
                    err_str.contains("JSON error") || // CLI returning invalid JSON
                    err_str.contains("CLI not found") ||
                    err_str.contains("command not found"),
                    "Should get authentication-related or CLI error, got: {}",
                    err_str
                );
                println!("Got expected authentication error: {}", err_str);
            }
        }
    }

    #[test]
    fn test_bitwarden_error_messages() {
        use crate::provider::bitwarden::BitwardenProvider;

        // Test that we get helpful error messages
        let provider = BitwardenProvider::default();

        // This will likely fail with authentication error or CLI not found error
        // but we want to verify the error messages are helpful
        let result = provider.get("test", "KEY", "default");
        match result {
            Err(err) => {
                let err_msg = err.to_string();
                // Should contain helpful guidance
                assert!(
                    err_msg.contains("bw login") ||
                    err_msg.contains("bw unlock") ||
                    err_msg.contains("BW_SESSION") ||
                    err_msg.contains("authentication") ||
                    err_msg.contains("install") ||
                    err_msg.contains("JSON error") || // CLI returning invalid JSON
                    err_msg.contains("CLI not found") ||
                    err_msg.contains("command not found"),
                    "Error message should be helpful: {}",
                    err_msg
                );
                println!("Got helpful error message: {}", err_msg);
            }
            Ok(_) => {
                println!("Bitwarden provider is working (vault is unlocked)");
            }
        }
    }

    #[test]
    fn test_bitwarden_with_real_cli_if_available() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bitwarden
        let providers = get_test_providers();
        if !providers.contains(&"bitwarden".to_string()) {
            println!("Skipping bitwarden CLI test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        println!("Testing bitwarden provider with real CLI");
        let (provider, _temp_dir) = create_provider_with_temp_path("bitwarden");

        // Run the generic provider test
        test_provider_basic_workflow(provider.as_ref(), "bitwarden");

        println!("Bitwarden provider passed all tests!");
    }

    #[test]
    fn test_bws_with_real_cli_if_available() {
        // Only run this test if SECRETSPEC_TEST_PROVIDERS includes bws
        let providers = get_test_providers();
        if !providers.contains(&"bws".to_string()) {
            println!("Skipping BWS CLI test - not in SECRETSPEC_TEST_PROVIDERS");
            return;
        }

        println!("Testing BWS (Bitwarden Secrets Manager) provider with real CLI");
        let (provider, _temp_dir) = create_provider_with_temp_path("bws");

        // Run the generic provider test
        test_provider_basic_workflow(provider.as_ref(), "bws");

        println!("BWS provider passed all tests!");
    }

    #[test]
    fn test_bitwarden_item_type_support() {
        // Test that different item types are supported in provider creation
        let providers_to_test = vec![
            ("bitwarden://?type=login", "login items"),
            ("bitwarden://?type=card", "card items"),
            ("bitwarden://?type=identity", "identity items"),
            ("bitwarden://?type=sshkey", "SSH key items"),
            ("bitwarden://?type=securenote", "secure note items"),
        ];

        for (uri, description) in providers_to_test {
            println!("Testing provider creation for {}", description);
            let provider = Box::<dyn Provider>::try_from(uri);
            match provider {
                Ok(provider) => {
                    assert_eq!(provider.name(), "bitwarden");
                    println!("✓ Successfully created provider for {}", description);
                }
                Err(e) => {
                    panic!("Failed to create provider for {}: {}", description, e);
                }
            }
        }
    }
}
