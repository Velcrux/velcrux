// Unit tests for `FileAuthorizer` and the auth module.
use crate::auth::{
    Authenticator, Authorizer, DeletionLimiter, DeletionPolicy, FileAuthorizer, Grant,
    MtlsAuthenticator, Op, PermSet, Role,
};
use crate::error::VelcruxError;
use crate::transport::identity::Identity;

fn identity(name: &str) -> Identity {
    Identity::new(name, "issuer", "cert")
}

// --- 1. Deny-by-default ---

#[test]
fn deny_by_default() {
    let authz = FileAuthorizer::new();
    let id = identity("anyone");
    assert!(matches!(
        authz.check(&id, Op::Upload, "data/file"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Download, "data/file"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::List, "data/"),
        Err(VelcruxError::Protocol(_))
    ));
    assert_eq!(authz.granted_permissions(&id).0, 0);
}

// --- 2. Granted permission allows ---

#[test]
fn granted_permission_allows() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("alice");
    let vpath = authz.check(&id, Op::Upload, "data/file.bin").unwrap();
    assert_eq!(vpath.as_str(), "data/file.bin");
}

// --- 3. Missing permission denies ---

#[test]
fn missing_permission_denies() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("alice");
    assert!(matches!(
        authz.check(&id, Op::Download, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::List, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 4. Admin does not imply transfer perms ---

#[test]
fn admin_does_not_imply_transfer_perms() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "admin".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::ADMIN,
    }]);
    let id = identity("admin");
    assert!(matches!(
        authz.check(&id, Op::Upload, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Download, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::List, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Sync, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Resume, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Delete, "data/file.bin"),
        Err(VelcruxError::Protocol(_))
    ));
    // Admin can do admin op.
    let vpath = authz.check(&id, Op::Admin, "data/file.bin").unwrap();
    assert_eq!(vpath.as_str(), "data/file.bin");
}

// --- 5. Longest prefix wins ---

#[test]
fn longest_prefix_wins() {
    let authz = FileAuthorizer::from_grants(vec![
        Grant {
            identity: "alice".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::UPLOAD,
        },
        Grant {
            identity: "alice".to_string(),
            path_prefix: "data/sensitive".to_string(),
            permissions: PermSet::UPLOAD | PermSet::DOWNLOAD,
        },
    ]);
    let id = identity("alice");
    // data/sensitive/x matches both grants; the longer one wins.
    let vpath = authz.check(&id, Op::Download, "data/sensitive/x").unwrap();
    assert_eq!(vpath.as_str(), "data/sensitive/x");
    // data/x only matches the broader grant (upload only).
    let vpath = authz.check(&id, Op::Upload, "data/x").unwrap();
    assert_eq!(vpath.as_str(), "data/x");
    assert!(matches!(
        authz.check(&id, Op::Download, "data/x"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 6. Whole-root grant ---

#[test]
fn whole_root_grant() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "ops".to_string(),
        path_prefix: "/".to_string(),
        permissions: PermSet::UPLOAD | PermSet::DOWNLOAD | PermSet::LIST,
    }]);
    let id = identity("ops");
    let vpath = authz.check(&id, Op::Upload, "anything/here").unwrap();
    assert_eq!(vpath.as_str(), "anything/here");
    let vpath = authz.check(&id, Op::List, "foo/bar").unwrap();
    assert_eq!(vpath.as_str(), "foo/bar");
}

// --- 7. Cross-identity isolation ---

#[test]
fn cross_identity_isolation() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let alice = identity("alice");
    let bob = identity("bob");
    assert!(authz.check(&alice, Op::Upload, "data/file").is_ok());
    assert!(matches!(
        authz.check(&bob, Op::Upload, "data/file"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 8. Component-boundary matching ---

#[test]
fn component_boundary_matching() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data/customerA".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("alice");
    // Exact match works.
    assert!(authz.check(&id, Op::Upload, "data/customerA").is_ok());
    assert!(authz.check(&id, Op::Upload, "data/customerA/file").is_ok());
    // data/customerA does NOT match data/customerAB/... (component boundary).
    assert!(matches!(
        authz.check(&id, Op::Upload, "data/customerAB/file"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 9. Path validation rejects traversal ---

#[test]
fn path_validation_rejects_traversal() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("alice");
    // Even though the grant covers "data", traversal is rejected before grant lookup.
    assert!(matches!(
        authz.check(&id, Op::Upload, "../etc/passwd"),
        Err(VelcruxError::Protocol(_))
    ));
    assert!(matches!(
        authz.check(&id, Op::Upload, "data/../../etc/passwd"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 10. Path validation rejects absolute paths ---

#[test]
fn path_validation_rejects_absolute() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("alice");
    assert!(matches!(
        authz.check(&id, Op::Upload, "/etc/passwd"),
        Err(VelcruxError::Protocol(_))
    ));
}

// --- 11. granted_permissions union ---

#[test]
fn granted_permissions_union() {
    let authz = FileAuthorizer::from_grants(vec![
        Grant {
            identity: "alice".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::UPLOAD,
        },
        Grant {
            identity: "alice".to_string(),
            path_prefix: "logs".to_string(),
            permissions: PermSet::DOWNLOAD | PermSet::LIST,
        },
    ]);
    let id = identity("alice");
    let perms = authz.granted_permissions(&id);
    assert!(perms.has(PermSet::UPLOAD));
    assert!(perms.has(PermSet::DOWNLOAD));
    assert!(perms.has(PermSet::LIST));
    assert!(!perms.has(PermSet::DELETE));
    assert!(!perms.has(PermSet::ADMIN));
}

// --- 12. granted_permissions empty for unknown identity ---

#[test]
fn granted_permissions_empty_unknown() {
    let authz = FileAuthorizer::from_grants(vec![Grant {
        identity: "alice".to_string(),
        path_prefix: "data".to_string(),
        permissions: PermSet::UPLOAD,
    }]);
    let id = identity("bob");
    assert_eq!(authz.granted_permissions(&id).0, 0);
}

// --- 13. Unknown permission string in TOML ---

#[test]
fn toml_unknown_permission_fails() {
    let toml_str = r#"
[[grant]]
identity = "alice"
path = "data"
permissions = ["upload", "bogus"]
"#;
    let tmp = std::env::temp_dir().join(format!(
        "velcrux-auth-unknown-perm-{}.toml",
        std::process::id()
    ));
    std::fs::write(&tmp, toml_str).unwrap();
    let result = FileAuthorizer::load(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(matches!(result, Err(VelcruxError::Config(_))));
}

// --- 14. Invalid grant path in TOML ---

#[test]
fn toml_invalid_grant_path_fails() {
    let toml_str = r#"
[[grant]]
identity = "alice"
path = "../escape"
permissions = ["upload"]
"#;
    let tmp = std::env::temp_dir().join(format!(
        "velcrux-auth-invalid-path-{}.toml",
        std::process::id()
    ));
    std::fs::write(&tmp, toml_str).unwrap();
    let result = FileAuthorizer::load(&tmp);
    let _ = std::fs::remove_file(&tmp);
    assert!(matches!(result, Err(VelcruxError::Config(_))));
}

// --- Extra: MtlsAuthenticator ---

#[test]
fn mtls_authenticator_passes_through() {
    let auth = MtlsAuthenticator::new();
    let id = identity("test-user");
    let verified = auth.authenticate(&id).unwrap();
    assert_eq!(verified.name, "test-user");
}

// --- 15. RBAC roles and permissions ---

#[test]
fn role_permissions_structure() {
    let admin = Role::Admin.permissions();
    assert!(admin.has(PermSet::ADMIN));
    assert!(admin.has(PermSet::UPLOAD));
    assert!(admin.has(PermSet::DOWNLOAD));
    assert!(admin.has(PermSet::DELETE));
    assert!(admin.has(PermSet::SYNC_DELETE));

    let operator = Role::Operator.permissions();
    assert!(!operator.has(PermSet::ADMIN));
    assert!(operator.has(PermSet::DELETE));
    assert!(!operator.has(PermSet::SYNC_DELETE));

    let writer = Role::SyncWriter.permissions();
    assert!(!writer.has(PermSet::ADMIN));
    assert!(!writer.has(PermSet::DELETE));
    assert!(!writer.has(PermSet::SYNC_DELETE));
    assert!(writer.has(PermSet::SYNC));

    let replica = Role::SyncReplica.permissions();
    assert!(!replica.has(PermSet::ADMIN));
    assert!(!replica.has(PermSet::DELETE));
    assert!(replica.has(PermSet::SYNC_DELETE));
    assert!(replica.has(PermSet::SYNC));

    let readonly = Role::ReadOnly.permissions();
    assert!(!readonly.has(PermSet::UPLOAD));
    assert!(readonly.has(PermSet::DOWNLOAD));
    assert!(readonly.has(PermSet::LIST));
}

#[test]
fn role_parsing_from_str() {
    assert_eq!("admin".parse::<Role>().unwrap(), Role::Admin);
    assert_eq!("operator".parse::<Role>().unwrap(), Role::Operator);
    assert_eq!("sync_writer".parse::<Role>().unwrap(), Role::SyncWriter);
    assert_eq!("sync-writer".parse::<Role>().unwrap(), Role::SyncWriter);
    assert_eq!("sync_replica".parse::<Role>().unwrap(), Role::SyncReplica);
    assert_eq!("sync-replica".parse::<Role>().unwrap(), Role::SyncReplica);
    assert_eq!("read_only".parse::<Role>().unwrap(), Role::ReadOnly);
    assert_eq!("readonly".parse::<Role>().unwrap(), Role::ReadOnly);
    assert!("invalid_role".parse::<Role>().is_err());
}

// --- 16. DeletionPolicy parsing and Limiter ---

#[test]
fn deletion_policy_parsing() {
    assert_eq!(
        "admin-only".parse::<DeletionPolicy>().unwrap(),
        DeletionPolicy::AdminOnly
    );
    assert_eq!(
        "explicit-grant".parse::<DeletionPolicy>().unwrap(),
        DeletionPolicy::ExplicitGrant
    );
    assert_eq!(
        "disabled".parse::<DeletionPolicy>().unwrap(),
        DeletionPolicy::Disabled
    );
    assert!(matches!(
        "rate-limited".parse::<DeletionPolicy>().unwrap(),
        DeletionPolicy::RateLimited { .. }
    ));
    assert!("unknown_policy".parse::<DeletionPolicy>().is_err());
}

#[test]
fn deletion_limiter_enforces_sliding_window() {
    let limiter = DeletionLimiter::new();
    let id = "backup-agent";

    // Allow 3 deletions in a 60-second window
    assert!(limiter.check_and_record(id, 3, 60));
    assert!(limiter.check_and_record(id, 3, 60));
    assert!(limiter.check_and_record(id, 3, 60));
    // 4th deletion is blocked
    assert!(!limiter.check_and_record(id, 3, 60));

    // Another identity is not blocked
    assert!(limiter.check_and_record("admin", 3, 60));

    // Resetting clears the history
    limiter.reset();
    assert!(limiter.check_and_record(id, 3, 60));
}

// --- 17. SyncDelete authorization checks ---

#[test]
fn sync_delete_requires_sync_delete_permission() {
    let id_replica = identity("replica");
    let id_writer = identity("writer");

    let authz = FileAuthorizer::from_grants(vec![
        Grant {
            identity: "replica".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::SYNC | PermSet::SYNC_DELETE,
        },
        Grant {
            identity: "writer".to_string(),
            path_prefix: "data".to_string(),
            permissions: PermSet::SYNC | PermSet::DELETE, // only standard delete, not sync_delete!
        },
    ]);

    // Replica can perform Op::SyncDelete
    assert!(authz
        .check(&id_replica, Op::SyncDelete, "data/file.txt")
        .is_ok());
    // Replica cannot perform single-file Op::Delete
    assert!(authz
        .check(&id_replica, Op::Delete, "data/file.txt")
        .is_err());

    // Writer cannot perform Op::SyncDelete
    assert!(authz
        .check(&id_writer, Op::SyncDelete, "data/file.txt")
        .is_err());
    // Writer can perform single-file Op::Delete
    assert!(authz.check(&id_writer, Op::Delete, "data/file.txt").is_ok());
}

// --- 18. TOML loading with role and sync_delete ---

#[test]
fn toml_grant_with_role_and_sync_delete() {
    let toml_str = r#"
[[grant]]
identity = "replica"
path = "data"
role = "sync_replica"

[[grant]]
identity = "custom"
path = "backup"
permissions = ["sync", "sync_delete"]
"#;
    let tmp = std::env::temp_dir().join(format!("velcrux-auth-role-{}.toml", std::process::id()));
    std::fs::write(&tmp, toml_str).unwrap();
    let authz = FileAuthorizer::load(&tmp).unwrap();
    let _ = std::fs::remove_file(&tmp);

    let id_rep = identity("replica");
    let perms_rep = authz.granted_permissions(&id_rep);
    assert!(perms_rep.has(PermSet::SYNC));
    assert!(perms_rep.has(PermSet::SYNC_DELETE));
    assert!(!perms_rep.has(PermSet::ADMIN));

    let id_custom = identity("custom");
    let perms_custom = authz.granted_permissions(&id_custom);
    assert!(perms_custom.has(PermSet::SYNC));
    assert!(perms_custom.has(PermSet::SYNC_DELETE));
}
