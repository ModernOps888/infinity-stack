pub fn permission_matches(granted: &str, required: &str) -> bool {
    let (gr, ga) = split(granted);
    let (rr, ra) = split(required);
    (gr == "*" || gr == rr) && (ga == "*" || ga == ra)
}

pub fn any_permission(granted: &[String], required: &str) -> bool {
    granted.iter().any(|g| permission_matches(g, required))
}

fn split(p: &str) -> (&str, &str) {
    p.split_once(':').unwrap_or((p, "*"))
}

pub const ROLE_SUPERADMIN: &str = "superadmin";
