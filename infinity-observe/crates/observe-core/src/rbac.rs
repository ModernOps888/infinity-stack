//! RBAC-lite permission matching for dashboard and bearer control-plane access.

pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_VIEWER: &str = "viewer";

pub fn permissions_for_role(role: &str) -> Vec<String> {
    match role {
        ROLE_ADMIN => vec!["*:*".into()],
        _ => vec![
            "logs:read".into(),
            "metrics:read".into(),
            "traces:read".into(),
            "alerts:read".into(),
            "stats:read".into(),
        ],
    }
}

pub fn permission_matches(granted: &str, required: &str) -> bool {
    let (gr, ga) = split(granted);
    let (rr, ra) = split(required);
    seg_match(gr, rr) && seg_match(ga, ra)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards() {
        assert!(permission_matches("*:*", "logs:read"));
        assert!(permission_matches("alerts:*", "alerts:delete"));
        assert!(!permission_matches("logs:read", "keys:create"));
    }
}
