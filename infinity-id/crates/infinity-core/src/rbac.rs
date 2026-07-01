//! Role-Based Access Control primitives.
//!
//! Permissions use a `resource:action` convention with `*` wildcards, e.g.
//! `users:read`, `users:*`, or `*:*` for super-admin. Scopes on access tokens
//! are checked against required permissions with the same matcher.

/// Returns true if `granted` satisfies the `required` permission.
///
/// `*` matches any single segment. Comparison is case-sensitive.
pub fn permission_matches(granted: &str, required: &str) -> bool {
    let (gr, ga) = split(granted);
    let (rr, ra) = split(required);
    seg_match(gr, rr) && seg_match(ga, ra)
}

/// Returns true if any of `granted` permissions satisfies `required`.
pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

fn split(p: &str) -> (&str, &str) {
    match p.split_once(':') {
        Some((r, a)) => (r, a),
        None => (p, "*"),
    }
}

fn seg_match(granted: &str, required: &str) -> bool {
    granted == "*" || granted == required
}

/// Well-known built-in roles seeded on first run.
pub const ROLE_SUPERADMIN: &str = "superadmin";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_USER: &str = "user";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(permission_matches("*:*", "users:read"));
        assert!(permission_matches("users:*", "users:delete"));
        assert!(permission_matches("users:read", "users:read"));
        assert!(!permission_matches("users:read", "users:delete"));
        assert!(!permission_matches("clients:*", "users:read"));
    }

    #[test]
    fn any() {
        let g = vec!["users:read".to_string(), "clients:*".to_string()];
        assert!(any_permission(&g, "clients:create"));
        assert!(!any_permission(&g, "roles:create"));
    }
}
