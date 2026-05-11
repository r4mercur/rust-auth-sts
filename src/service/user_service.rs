use crate::repository::memory::{UserStore, User};

#[derive(Clone)]
pub struct UserService {
    store: UserStore,
}

impl UserService {
    pub fn new(store: UserStore) -> Self { Self { store } }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<&User> {
        let u = self.store.get(username)?;
        if u.password == password { Some(u) } else { None }
    }

    pub fn is_scope_allowed(&self, user: &User, scope: &str) -> bool {
        scope.split_whitespace().all(|s| user.allowed_scopes.iter().any(|a| a == s))
    }
}