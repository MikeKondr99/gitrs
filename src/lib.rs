#![feature(slice_as_chunks)]
#![feature(array_chunks)]

mod sha1;
use std::path::{Path, PathBuf};

pub enum GitObject
{
    Blob(Vec<u8>),
    Tree,
    Commit,
}



pub struct GitRepository
{
    path: PathBuf,
}

impl GitRepository {

    pub fn new(path: &Path) -> GitRepository
    {
        GitRepository { path: path.to_path_buf() }
    }

}




#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
    }
}
