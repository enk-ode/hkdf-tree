// hkdf-tree — deterministic hierarchical passphrase derivation
// SPDX-License-Identifier: BSD-2-Clause

//! Inventory schema and loader.
//!
//! The inventory is the user-owned source of truth for what gets derived.
//! It is a YAML document defining domains, realms, purposes, and per-version
//! encoding parameters. This module owns the schema types, YAML parsing, and
//! structural validation.

use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;

use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

/// Top-level inventory document.
///
/// All schema structs reject unknown fields: a typo like `statu:` or
/// `lenght:` must fail loudly instead of silently falling back to a
/// default, because the inventory is the sole source of truth for
/// derivation parameters.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// Schema version of the YAML document itself. This tool currently
    /// accepts schema version 1.
    pub schema_version: u32,
    /// Domains keyed by name (e.g., `alice`, `acme-corp`).
    #[serde(deserialize_with = "de_unique_map")]
    pub domains: BTreeMap<String, Domain>,
}

/// One responsibility domain within an inventory.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Domain {
    /// Public HKDF salt for this domain. Not a secret; provides
    /// domain separation between distinct users or organizations.
    pub salt: String,
    /// Optional free-text description shown in listings and reports.
    #[serde(default)]
    pub description: Option<String>,
    /// Realms keyed by name (e.g., `laptop`, `phone`, `github`).
    #[serde(deserialize_with = "de_unique_map")]
    pub realms: BTreeMap<String, Realm>,
}

/// A container of related credentials within a domain.
///
/// Realms correspond either to a device (`laptop`, `phone`) or to a
/// service (`proton`, `github`) that owns the credentials collected
/// beneath them.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Realm {
    /// Optional kind hint for reports (e.g., `phone-graphene`,
    /// `workstation-freebsd`, `cloud-service`).
    #[serde(default)]
    pub kind: Option<String>,
    /// Optional free-text description.
    #[serde(default)]
    pub description: Option<String>,
    /// Purposes keyed by name (e.g., `owner-lockscreen`, `account`).
    #[serde(deserialize_with = "de_unique_map")]
    pub purposes: BTreeMap<String, Purpose>,
}

/// A specific role of a credential within a realm.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Purpose {
    /// Optional free-text description of what this credential authenticates.
    #[serde(default)]
    pub usage: Option<String>,
    /// Versions of this purpose keyed by integer version number.
    /// Multiple entries allow rotation (v1 retired, v2 active).
    #[serde(deserialize_with = "de_unique_map")]
    pub versions: BTreeMap<u32, Version>,
}

/// One concrete version of a purpose.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Version {
    /// How to turn the raw HKDF output into a usable secret.
    pub encoding: Encoding,
    /// How this secret is produced.
    pub derivation: Derivation,
    /// Lifecycle state of this version.
    #[serde(default = "default_status")]
    pub status: Status,
    /// Whether the user commits this to active memory (informational).
    #[serde(default)]
    pub memorized: Option<bool>,
    /// Paper-backup destinations (informational; free-form strings such
    /// as `home-safe`, `bank-vault`, `wallet`).
    #[serde(default)]
    pub paper_backup: Vec<String>,
    /// Free-form notes surfaced in reports.
    #[serde(default)]
    pub notes: Option<String>,
}

/// Encoding of the raw HKDF output into a user-visible secret.
///
/// The tagged enum representation matches YAML like:
/// ```yaml
/// encoding:
///   type: diceware
///   wordlist: eff_large
///   length: 8
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Encoding {
    /// Diceware passphrase: `length` words drawn from `wordlist`.
    Diceware {
        /// Name of the wordlist to use (e.g., `eff_large`).
        /// Wordlist files are resolved outside this module.
        wordlist: String,
        /// Number of words in the passphrase.
        length: usize,
    },
    /// Alphanumeric passphrase of `length` characters.
    Alphanumeric {
        /// Number of characters in the output.
        length: usize,
    },
    /// Numeric PIN of `length` digits.
    Numeric {
        /// Number of digits in the output.
        length: usize,
    },
    /// Raw base64-encoded output derived from `bytes` HKDF bytes.
    Base64 {
        /// Number of HKDF output bytes to encode.
        bytes: usize,
    },
}

/// How a version's secret is produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Derivation {
    /// Deterministically derived from the master seed via HKDF.
    Hkdf,
    /// Manually chosen (out of band); the inventory only documents its
    /// existence. This tool will not attempt to derive it.
    Manual,
    /// Generated by an external service (e.g., 2FA recovery codes,
    /// service-issued app passwords). Documented only; not derivable.
    ServiceGenerated,
}

/// Lifecycle status of a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    /// Currently in use.
    Active,
    /// Superseded by a newer version; kept for documentation.
    Retired,
    /// Placeholder; the credential is planned but not yet materialized.
    Reserved,
}

fn default_status() -> Status {
    Status::Active
}

/// Deserialize a mapping into a `BTreeMap`, rejecting duplicate keys.
///
/// Plain `BTreeMap` deserialization silently keeps the last occurrence of a
/// duplicated key — in an inventory that means a merge or copy-paste mistake
/// would change derivation parameters without any diagnostic. Every mapping
/// level of the schema goes through this helper instead.
fn de_unique_map<'de, D, K, V>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord + fmt::Display,
    V: Deserialize<'de>,
{
    struct UniqueMapVisitor<K, V>(PhantomData<(K, V)>);

    impl<'de, K, V> Visitor<'de> for UniqueMapVisitor<K, V>
    where
        K: Deserialize<'de> + Ord + fmt::Display,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a mapping with unique keys")
        }

        fn visit_map<A>(self, mut access: A) -> Result<Self::Value, A::Error>
        where
            A: MapAccess<'de>,
        {
            use serde::de::Error as _;
            let mut map = BTreeMap::new();
            while let Some((key, value)) = access.next_entry::<K, V>()? {
                if map.contains_key(&key) {
                    return Err(A::Error::custom(format!("duplicate key: {key}")));
                }
                map.insert(key, value);
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(UniqueMapVisitor(PhantomData))
}

/// Errors that can arise while loading or validating an inventory.
#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    /// YAML syntax or type-shape mismatch.
    #[error("YAML parse error: {0}")]
    Parse(#[from] serde_yaml_ng::Error),
    /// Unsupported schema version.
    #[error("unsupported schema_version: {0} (this tool supports version 1)")]
    UnsupportedSchemaVersion(u32),
    /// A name in the hierarchy does not match the canonicalization rule.
    #[error(
        "invalid name {name:?} at {path}: names must be lowercase ASCII letters, digits, and hyphens"
    )]
    InvalidName {
        /// Path within the inventory tree, e.g., `domains.alice.realms.laptop`.
        path: String,
        /// The offending name.
        name: String,
    },
    /// A domain, realm, or purpose has no children (structurally empty).
    #[error("empty container at {path}: expected at least one child")]
    EmptyContainer {
        /// Path within the inventory tree.
        path: String,
    },
}

/// A single derivable entry, flattened from the tree for iteration.
#[derive(Debug, Clone)]
pub struct Entry<'a> {
    /// The reconstructed hierarchical info-string used for HKDF derivation.
    /// Format: `<domain>/<realm>/<purpose>-v<N>`.
    pub info_string: String,
    /// The purpose's free-text usage description, if declared.
    pub usage: Option<&'a str>,
    /// The domain's salt.
    pub salt: &'a str,
    /// Reference to the version metadata.
    pub version: &'a Version,
}

impl Inventory {
    /// Parse and validate an inventory from a YAML string.
    pub fn from_yaml_str(s: &str) -> Result<Self, InventoryError> {
        let inv: Inventory = serde_yaml_ng::from_str(s)?;
        inv.validate()?;
        Ok(inv)
    }

    /// Find a single entry by its full info-string
    /// (`<domain>/<realm>/<purpose>-v<N>`), if present.
    pub fn find_entry(&self, info_string: &str) -> Option<Entry<'_>> {
        self.entries().find(|e| e.info_string == info_string)
    }

    /// Walk the tree and return one [`Entry`] per (domain, realm, purpose, version).
    ///
    /// Iteration order is deterministic (sorted by name at each level, then
    /// by version number), so downstream consumers (reports, listings) always
    /// see the same sequence.
    pub fn entries(&self) -> impl Iterator<Item = Entry<'_>> {
        self.domains.iter().flat_map(|(d_name, domain)| {
            domain.realms.iter().flat_map(move |(r_name, realm)| {
                realm.purposes.iter().flat_map(move |(p_name, purpose)| {
                    purpose.versions.iter().map(move |(v_num, version)| Entry {
                        info_string: format!("{d_name}/{r_name}/{p_name}-v{v_num}"),
                        usage: purpose.usage.as_deref(),
                        salt: &domain.salt,
                        version,
                    })
                })
            })
        })
    }

    fn validate(&self) -> Result<(), InventoryError> {
        if self.schema_version != 1 {
            return Err(InventoryError::UnsupportedSchemaVersion(
                self.schema_version,
            ));
        }

        if self.domains.is_empty() {
            return Err(InventoryError::EmptyContainer {
                path: "domains".to_string(),
            });
        }

        for (d_name, domain) in &self.domains {
            validate_name(d_name, "domains")?;

            if domain.realms.is_empty() {
                return Err(InventoryError::EmptyContainer {
                    path: format!("domains.{d_name}.realms"),
                });
            }

            for (r_name, realm) in &domain.realms {
                validate_name(r_name, &format!("domains.{d_name}.realms"))?;

                if realm.purposes.is_empty() {
                    return Err(InventoryError::EmptyContainer {
                        path: format!("domains.{d_name}.realms.{r_name}.purposes"),
                    });
                }

                for (p_name, purpose) in &realm.purposes {
                    validate_name(
                        p_name,
                        &format!("domains.{d_name}.realms.{r_name}.purposes"),
                    )?;

                    if purpose.versions.is_empty() {
                        return Err(InventoryError::EmptyContainer {
                            path: format!(
                                "domains.{d_name}.realms.{r_name}.purposes.{p_name}.versions"
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

fn validate_name(name: &str, path: &str) -> Result<(), InventoryError> {
    if name.is_empty() {
        return Err(InventoryError::InvalidName {
            path: path.to_string(),
            name: name.to_string(),
        });
    }
    let ok = name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
    if !ok {
        return Err(InventoryError::InvalidName {
            path: path.to_string(),
            name: name.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indoc::indoc;

    fn minimal_yaml() -> &'static str {
        indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: "alice-hkdf-v1"
                realms:
                  laptop:
                    kind: workstation-linux
                    purposes:
                      fde-daily:
                        usage: "geli slot 0 unlock"
                        versions:
                          1:
                            encoding:
                              type: diceware
                              wordlist: eff_large
                              length: 8
                            derivation: hkdf
                            memorized: true
                            paper_backup: [home-safe, bank-vault]
        "#}
    }

    #[test]
    fn loads_minimal_inventory() {
        let inv = Inventory::from_yaml_str(minimal_yaml()).expect("loads");
        assert_eq!(inv.schema_version, 1);
        assert_eq!(inv.domains.len(), 1);
        let alice = &inv.domains["alice"];
        assert_eq!(alice.salt, "alice-hkdf-v1");
        let laptop = &alice.realms["laptop"];
        assert_eq!(laptop.kind.as_deref(), Some("workstation-linux"));
        let fde = &laptop.purposes["fde-daily"];
        let v1 = &fde.versions[&1];
        assert_eq!(v1.derivation, Derivation::Hkdf);
        assert_eq!(v1.status, Status::Active);
        assert_eq!(v1.memorized, Some(true));
        assert_eq!(v1.paper_backup, vec!["home-safe", "bank-vault"]);
        match &v1.encoding {
            Encoding::Diceware { wordlist, length } => {
                assert_eq!(wordlist, "eff_large");
                assert_eq!(*length, 8);
            }
            _ => panic!("expected diceware"),
        }
    }

    #[test]
    fn entries_produces_correct_info_string() {
        let inv = Inventory::from_yaml_str(minimal_yaml()).expect("loads");
        let entries: Vec<_> = inv.entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].info_string, "alice/laptop/fde-daily-v1");
        assert_eq!(entries[0].salt, "alice-hkdf-v1");
    }

    #[test]
    fn multiple_versions_iterate_in_order() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: "s"
                realms:
                  laptop:
                    purposes:
                      fde-daily:
                        versions:
                          2:
                            encoding: {type: diceware, wordlist: eff_large, length: 8}
                            derivation: hkdf
                            status: active
                          1:
                            encoding: {type: diceware, wordlist: eff_large, length: 8}
                            derivation: hkdf
                            status: retired
        "#};
        let inv = Inventory::from_yaml_str(yaml).expect("loads");
        let entries: Vec<_> = inv.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].info_string, "alice/laptop/fde-daily-v1");
        assert_eq!(entries[1].info_string, "alice/laptop/fde-daily-v2");
    }

    #[test]
    fn multiple_domains_iterate_alphabetically() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              charlie:
                salt: c
                realms:
                  x:
                    purposes:
                      p:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
              alice:
                salt: a
                realms:
                  x:
                    purposes:
                      p:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
              bob:
                salt: b
                realms:
                  x:
                    purposes:
                      p:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
        "#};
        let inv = Inventory::from_yaml_str(yaml).expect("loads");
        let names: Vec<_> = inv
            .entries()
            .map(|e| e.info_string.split('/').next().unwrap().to_string())
            .collect();
        assert_eq!(names, vec!["alice", "bob", "charlie"]);
    }

    #[test]
    fn rejects_unsupported_schema_version() {
        let yaml = "schema_version: 2\ndomains: {}\n";
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        match err {
            InventoryError::UnsupportedSchemaVersion(2) => {}
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejects_uppercase_name() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              Alice:
                salt: s
                realms:
                  laptop:
                    purposes:
                      fde:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
        "#};
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        match err {
            InventoryError::InvalidName { name, .. } => assert_eq!(name, "Alice"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejects_name_with_underscore() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  my_laptop:
                    purposes:
                      fde:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
        "#};
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        match err {
            InventoryError::InvalidName { name, .. } => assert_eq!(name, "my_laptop"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejects_empty_domains() {
        let yaml = "schema_version: 1\ndomains: {}\n";
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        match err {
            InventoryError::EmptyContainer { path } => assert_eq!(path, "domains"),
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejects_realm_without_purposes() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  laptop:
                    purposes: {}
        "#};
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        match err {
            InventoryError::EmptyContainer { path } => {
                assert_eq!(path, "domains.alice.realms.laptop.purposes")
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn rejects_duplicate_purpose_key() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  phone:
                    purposes:
                      pin:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
                      pin:
                        versions:
                          1:
                            encoding: {type: numeric, length: 6}
                            derivation: hkdf
        "#};
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate key"),
            "expected duplicate-key error, got: {err}"
        );
    }

    #[test]
    fn rejects_duplicate_version_key() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  phone:
                    purposes:
                      pin:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
                          1:
                            encoding: {type: numeric, length: 6}
                            derivation: hkdf
        "#};
        let err = Inventory::from_yaml_str(yaml).unwrap_err();
        assert!(
            err.to_string().contains("duplicate key"),
            "expected duplicate-key error, got: {err}"
        );
    }

    #[test]
    fn rejects_unknown_field_in_version() {
        // A typo'd field name must fail loudly, not fall back to a default.
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  phone:
                    purposes:
                      pin:
                        versions:
                          1:
                            encoding: {type: numeric, length: 4}
                            derivation: hkdf
                            statu: retired
        "#};
        assert!(Inventory::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_field_in_encoding() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  phone:
                    purposes:
                      pin:
                        versions:
                          1:
                            encoding: {type: numeric, lenght: 4}
                            derivation: hkdf
        "#};
        assert!(Inventory::from_yaml_str(yaml).is_err());
    }

    #[test]
    fn accepts_service_generated_and_manual() {
        let yaml = indoc! {r#"
            schema_version: 1
            domains:
              alice:
                salt: s
                realms:
                  proton:
                    purposes:
                      recovery-codes:
                        versions:
                          1:
                            encoding: {type: base64, bytes: 32}
                            derivation: service-generated
                            status: reserved
                      old-master:
                        versions:
                          1:
                            encoding: {type: alphanumeric, length: 47}
                            derivation: manual
                            status: active
        "#};
        let inv = Inventory::from_yaml_str(yaml).expect("loads");
        let entries: Vec<_> = inv.entries().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].version.derivation, Derivation::Manual);
        assert_eq!(entries[0].version.status, Status::Active);
        assert_eq!(entries[1].version.derivation, Derivation::ServiceGenerated);
        assert_eq!(entries[1].version.status, Status::Reserved);
    }
}
