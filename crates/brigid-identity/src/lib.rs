pub mod attributes;
pub mod error;
pub mod profile;
pub mod recovery;
pub mod root_id;
pub mod templates;
pub mod username;
pub mod vsid;

pub use attributes::{Attribute, Attributes, Need, Scope, validate_attributes};
pub use error::{Error, Result};
pub use profile::{validate_description, validate_logo, validate_name};
pub use recovery::{CodeError, RecoveryCode};
pub use root_id::RootId;
pub use templates::{GROUPS, IdentityTemplate, TEMPLATES, default_templates, template};
pub use username::generate_username;
pub use vsid::{Vsid, identity_vsid};
