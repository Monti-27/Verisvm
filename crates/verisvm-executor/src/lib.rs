mod error;
mod git;
mod materialize;
mod resolver;
mod tree;

pub use error::{Error, Result};
pub use resolver::{GitSourceResolver, ResolvedSource};
