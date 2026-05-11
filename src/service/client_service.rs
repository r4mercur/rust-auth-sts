use crate::repository::memory::{ClientStore, Client};

#[derive(Clone)]
pub struct ClientService {
    store: ClientStore
}
impl ClientService {
    pub fn new(store: ClientStore) -> Self { Self { store } }
    pub fn authenticate(&self, id: &str, secret: Option<&str>) -> Option<&Client> {
        let c = self.store.get(id)?;
        match secret {
            Some(s) if s == c.secret => Some(c),
            // TODO: mTLS-gebundene Clients erlauben
            _ => None,
        }
    }
    pub fn is_scope_allowed(&self, c: &Client, scope: &str) -> bool {
        c.allowed_scopes.iter().any(|s| s == scope)
    }
    pub fn is_aud_allowed(&self, c: &Client, aud: &str) -> bool {
        c.allowed_audiences.iter().any(|a| a == aud)
    }
}
