//! Configuration policies for the built-in inspectors.

mod certificate;
mod environment;
mod nickel;
mod policy;

pub use certificate::load_certificate_config;
pub use environment::{load_environment_policy, EnvironmentPolicy};
pub use policy::{CertificateConfig, CertificateMode, CertificatePolicy};

