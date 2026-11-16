//! SHA-256 of a byte stream, for `GET /api/m2100/sha256/{name}`: the add-on
//! compares this with its own copy before it deletes anything on the device.

use futures::{Stream, TryStreamExt};

/// Lowercase hex SHA-256 of every chunk in order. Any item error is an `Err`;
/// a partial hash is never returned.
pub async fn sha256_of_stream<S, B, E>(s: S) -> std::io::Result<String>
where
    S: Stream<Item = Result<B, E>>,
    B: AsRef<[u8]>,
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    use sha2::{Digest, Sha256};
    let mut s = std::pin::pin!(s);
    let mut hasher = Sha256::new();
    while let Some(chunk) = s.try_next().await.map_err(std::io::Error::other)? {
        hasher.update(chunk.as_ref());
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn ok(chunks: Vec<&'static [u8]>) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> {
        stream::iter(chunks.into_iter().map(|c| Ok(c.to_vec())))
    }

    #[tokio::test]
    async fn known_vectors() {
        assert_eq!(sha256_of_stream(ok(vec![])).await.unwrap(), EMPTY);
        assert_eq!(sha256_of_stream(ok(vec![b"abc"])).await.unwrap(), ABC);
    }

    #[tokio::test]
    async fn split_points_do_not_matter() {
        let one = sha256_of_stream(ok(vec![b"abcdefg"])).await.unwrap();
        let seven = sha256_of_stream(ok(vec![b"a", b"b", b"c", b"d", b"e", b"f", b"g"]))
            .await
            .unwrap();
        assert_eq!(one, seven);
        assert_eq!(one.len(), 64);
    }

    #[tokio::test]
    async fn an_error_item_is_an_error_not_a_hash() {
        let s = stream::iter(vec![
            Ok(b"ab".to_vec()),
            Err(std::io::Error::other("boom")),
            Ok(b"c".to_vec()),
        ]);
        assert!(sha256_of_stream(s).await.is_err());
    }

    #[test]
    fn route_is_get_only() {
        let main = include_str!("../main.rs");
        let line = main
            .lines()
            .find(|l| l.contains("\"/api/m2100/sha256/{name}\", get("))
            .expect("route registered with get(");
        assert!(!line.contains("post("));
    }
}
