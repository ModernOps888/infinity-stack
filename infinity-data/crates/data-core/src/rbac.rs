pub fn permission_matches(granted: &str, required: &str) -> bool {
    let (gr, ga) = split(granted);
    let (rr, ra) = split(required);
    seg_match(gr, rr) && seg_match(ga, ra)
}

pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

fn split(p: &str) -> (&str, &str) {
    p.split_once(':').unwrap_or((p, "*"))
}

fn seg_match(granted: &str, required: &str) -> bool {
    granted == "*" || granted == required
}

pub const ROLE_SUPERADMIN: &str = "superadmin";
pub const ROLE_ADMIN: &str = "admin";
pub const ROLE_USER: &str = "user";
