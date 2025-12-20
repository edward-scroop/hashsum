pub mod md5;

pub trait Hash {
    fn hash_data(message: &mut Vec<u8>) -> String;
}
