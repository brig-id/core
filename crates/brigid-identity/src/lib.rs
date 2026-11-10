pub mod alias;
pub mod error;
pub mod identifier;
pub mod profile;
pub mod root_id;
pub mod templates;
pub mod vsid;

pub use alias::PrivateAlias;
pub use error::{Error, Result};
pub use identifier::{IdentifierKind, parse_identifier};
pub use profile::{identity_did, validate_description, validate_logo, validate_name};
pub use root_id::RootId;
pub use templates::{IdentityTemplate, TEMPLATES, default_templates, template};
pub use vsid::{Vsid, compute_vsid, derive_vsid_salt};
