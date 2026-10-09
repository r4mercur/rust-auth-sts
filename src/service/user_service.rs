use crate::{crypto::password::verify_secret, repository::memory::{UserStore, User}, service::scope};

#[derive(Clone)]
pub struct UserService {
    store: UserStore,
}

impl UserService {
    pub fn new(store: UserStore) -> Self { Self { store } }

    pub fn authenticate(&self, username: &str, password: &str) -> Option<User> {
        match self.store.get(username) {
            Some(u) if verify_secret(&u.password_hash, password) => Some(u.clone()),
            Some(_) => None,
            None => {
                verify_secret(self.store.dummy_hash(), password);
                None
            }
        }
    }

    pub fn is_scope_allowed(&self, user: &User, scope: &str) -> bool {
        scope::all_allowed(scope, &user.allowed_scopes)
    }

    pub fn is_aud_allowed(&self, user: &User, aud: &str) -> bool {
        user.allowed_audiences.iter().any(|a| a == aud)
    }
}
