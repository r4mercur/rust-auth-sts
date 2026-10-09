use crate::{crypto::password::verify_secret, repository::memory::{ClientStore, Client}, service::scope};

#[derive(Clone)]
pub struct ClientService {
    store: ClientStore
}
impl ClientService {
    pub fn new(store: ClientStore) -> Self { Self { store } }

    pub fn authenticate(&self, id: &str, secret: &str) -> Option<Client> {
        match self.store.get(id) {
            Some(c) if verify_secret(&c.secret_hash, secret) => Some(c.clone()),
            Some(_) => None,
            None => {
                verify_secret(self.store.dummy_hash(), secret);
                None
            }
        }
    }
    pub fn is_scope_allowed(&self, c: &Client, scope: &str) -> bool {
        scope::all_allowed(scope, &c.allowed_scopes)
    }
    pub fn is_aud_allowed(&self, c: &Client, aud: &str) -> bool {
        c.allowed_audiences.iter().any(|a| a == aud)
    }
}
