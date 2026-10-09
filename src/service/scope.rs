pub fn normalize(scope: &str) -> Option<String> {
    let mut scopes: Vec<&str> = Vec::new();
    for s in scope.split_whitespace() {
        if !scopes.contains(&s) {
            scopes.push(s);
        }
    }
    (!scopes.is_empty()).then(|| scopes.join(" "))
}

pub fn all_allowed(scope: &str, allowed: &[String]) -> bool {
    let mut scopes = scope.split_whitespace().peekable();
    scopes.peek().is_some() && scopes.all(|s| allowed.iter().any(|a| a == s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_dedupes_and_trims() {
        assert_eq!(normalize("  a b  a ").as_deref(), Some("a b"));
        assert_eq!(normalize("   "), None);
    }

    #[test]
    fn all_allowed_requires_every_scope() {
        let allowed = vec!["a".to_string(), "b".to_string()];
        assert!(all_allowed("a b", &allowed));
        assert!(!all_allowed("a c", &allowed));
        assert!(!all_allowed("", &allowed));
    }
}
