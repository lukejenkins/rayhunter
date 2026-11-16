//! Qualcomm Mobile Diagnostic Log (QMDL) files have a very simple format: just
//! a series of of concatenated HDLC encapsulated diag::Message structs.
//! QmdlReader and QmdlWriter can read and write MessagesContainers to and from
//! QMDL files.

use std::io::ErrorKind;
use std::pin::Pin;
use std::task::Poll;

use crate::diag::{DiagParsingError, MESSAGE_TERMINATOR, Message, MessagesContainer};

use async_compression::tokio::bufread::GzipDecoder;
use async_compression::tokio::write::GzipEncoder;
use futures::TryStream;
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncSeek, AsyncSeekExt, AsyncWrite, AsyncWriteExt,
    BufReader,
};

const GZIP_MAGIC_NUMBER: u16 = 0x1f8b;

pub struct QmdlWriter<T>
where
    T: AsyncWrite + Unpin,
{
    writer: GzipEncoder<T>,
}

impl<T> QmdlWriter<T>
where
    T: AsyncWrite + AsyncSeek + Unpin,
{
    pub fn new(writer: T) -> Self {
        let gzip_writer = GzipEncoder::new(writer);
        QmdlWriter {
            writer: gzip_writer,
        }
    }

    pub async fn size(&mut self) -> std::io::Result<usize> {
        let size = self.writer.get_mut().stream_position().await?;
        Ok(size as usize)
    }

    pub async fn write_container(&mut self, container: &MessagesContainer) -> std::io::Result<()> {
        for msg in &container.messages {
            self.writer.write_all(&msg.data).await?;
        }
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn close(mut self) -> std::io::Result<usize> {
        self.writer.shutdown().await?;
        self.size().await
    }
}

#[derive(Debug)]
enum QmdlReaderSource<T> {
    Compressed {
        reader: GzipDecoder<BufReader<T>>,
        eof: bool,
    },
    Uncompressed {
        reader: T,
    },
}

#[derive(Debug)]
struct QmdlAsyncReader<T> {
    source: QmdlReaderSource<T>,
}

impl<T> QmdlAsyncReader<T>
where
    T: AsyncRead,
{
    pub fn new(reader: T, compressed: bool) -> Self {
        let source = if compressed {
            QmdlReaderSource::Compressed {
                reader: GzipDecoder::new(BufReader::new(reader)),
                eof: false,
            }
        } else {
            QmdlReaderSource::Uncompressed { reader }
        };
        Self { source }
    }
}

impl<T> AsyncRead for QmdlAsyncReader<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut self.get_mut().source {
            QmdlReaderSource::Compressed { reader, eof } => {
                // if we already determined we've reached the Gzip EOF, don't read more
                if *eof {
                    return Poll::Ready(Ok(()));
                }

                match Pin::new(reader).poll_read(cx, buf) {
                    // if we hit an unexpected EOF in a Gzip file, it shouldn't
                    // be considered fatal, just a truncated file. mark that
                    // we're done and return the result as usual
                    Poll::Ready(Err(err)) if err.kind() == ErrorKind::UnexpectedEof => {
                        *eof = true;
                        Poll::Ready(Ok(()))
                    }
                    res => res,
                }
            }
            QmdlReaderSource::Uncompressed { reader } => Pin::new(reader).poll_read(cx, buf),
        }
    }
}

#[derive(Debug)]
pub struct QmdlMessageReader<T>
where
    T: AsyncRead,
{
    buf_reader: BufReader<QmdlAsyncReader<T>>,
    max_frame: Option<usize>,
}

async fn is_gzip_stream<T>(mut reader: T) -> std::io::Result<bool>
where
    T: AsyncRead + AsyncSeek + Unpin,
{
    let magic_number = reader.read_u16().await?;
    reader.rewind().await?;
    // this is safe because 0x1f8b.... doesn't overlap with any known
    // diag::DataType values
    Ok(magic_number == GZIP_MAGIC_NUMBER)
}

impl<T> QmdlMessageReader<T>
where
    T: AsyncRead + AsyncSeek + Unpin,
{
    pub async fn new(mut reader: T) -> std::io::Result<Self> {
        let compressed = is_gzip_stream(&mut reader).await.unwrap_or(false);
        Ok(QmdlMessageReader {
            buf_reader: BufReader::new(QmdlAsyncReader::new(reader, compressed)),
            max_frame: None,
        })
    }

    /// Bound the size of a single frame (bytes up to and including the
    /// terminator) read by `get_next_message` (and so `into_message_stream`).
    /// A frame that reaches `max` bytes without a terminator makes
    /// `get_next_message` return an `InvalidData` error, having buffered at
    /// most `max` bytes. Unset (the default) is unbounded, as before.
    /// This does not affect `into_qmdl_stream`, which the device's download
    /// endpoint serves.
    pub fn with_max_frame(mut self, max: usize) -> Self {
        self.max_frame = Some(max);
        self
    }

    pub fn is_compressed(&self) -> bool {
        matches!(
            self.buf_reader.get_ref().source,
            QmdlReaderSource::Compressed { .. }
        )
    }

    pub fn into_qmdl_stream(self) -> impl TryStream<Ok = Vec<u8>, Error = std::io::Error> {
        futures::stream::try_unfold(self, |mut reader| async {
            let mut buf = vec![];
            match reader
                .buf_reader
                .read_until(MESSAGE_TERMINATOR, &mut buf)
                .await
            {
                Err(err) => Err(err),
                Ok(0) => Ok(None),
                Ok(_) => Ok(Some((buf, reader))),
            }
        })
    }

    pub fn into_message_stream(
        self,
    ) -> impl TryStream<Ok = Result<Message, DiagParsingError>, Error = std::io::Error> {
        futures::stream::try_unfold(self, |mut reader| async {
            match reader.get_next_message().await? {
                Some(res) => Ok(Some((res, reader))),
                None => Ok(None),
            }
        })
    }

    pub async fn get_next_message(
        &mut self,
    ) -> Result<Option<Result<Message, DiagParsingError>>, std::io::Error> {
        let mut buf = vec![];
        let Some(max) = self.max_frame else {
            if self
                .buf_reader
                .read_until(MESSAGE_TERMINATOR, &mut buf)
                .await?
                == 0
            {
                return Ok(None);
            }
            return Ok(Some(Message::from_hdlc(&buf)));
        };

        // bounded read: never hold more than `max` bytes of one frame
        loop {
            let avail = self.buf_reader.fill_buf().await?;
            if avail.is_empty() {
                break;
            }
            let room = max - buf.len();
            if room == 0 {
                return Err(std::io::Error::new(
                    ErrorKind::InvalidData,
                    "frame exceeds limit",
                ));
            }
            let chunk = &avail[..avail.len().min(room)];
            match chunk.iter().position(|b| *b == MESSAGE_TERMINATOR) {
                Some(i) => {
                    buf.extend_from_slice(&chunk[..=i]);
                    self.buf_reader.consume(i + 1);
                    break;
                }
                None => {
                    let n = chunk.len();
                    buf.extend_from_slice(chunk);
                    self.buf_reader.consume(n);
                }
            }
        }
        if buf.is_empty() {
            return Ok(None);
        }
        Ok(Some(Message::from_hdlc(&buf)))
    }
}

impl<T> AsyncRead for QmdlMessageReader<T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().buf_reader).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod test {
    use std::io::Cursor;

    use crate::diag::{DataType, HdlcEncapsulatedMessage, diaglog::test::get_test_message};

    use super::*;

    fn get_test_messages() -> (Vec<HdlcEncapsulatedMessage>, Vec<Message>) {
        let mut hdlcs = Vec::new();
        let mut messages = Vec::new();
        for i in 10..20 {
            let (hdlc, msg) = get_test_message(&[i]);
            hdlcs.push(hdlc);
            messages.push(msg);
        }
        (hdlcs, messages)
    }

    // returns a byte array consisting of concatenated HDLC encapsulated
    // test messages
    fn get_test_message_bytes() -> Vec<u8> {
        let (hdlcs, _) = get_test_messages();
        hdlcs.iter().flat_map(|msg| msg.data.clone()).collect()
    }

    fn get_test_containers() -> Vec<MessagesContainer> {
        let (hdlcs, _) = get_test_messages();
        let (hdlcs1, hdlcs2) = hdlcs.split_at(5);
        vec![
            MessagesContainer {
                data_type: DataType::UserSpace,
                num_messages: hdlcs1.len() as u32,
                messages: hdlcs1.to_vec(),
            },
            MessagesContainer {
                data_type: DataType::UserSpace,
                num_messages: hdlcs2.len() as u32,
                messages: hdlcs2.to_vec(),
            },
        ]
    }

    #[tokio::test]
    async fn test_qmdl_reader() {
        let mut buf = Cursor::new(get_test_message_bytes());
        let mut reader = QmdlMessageReader::new(&mut buf).await.unwrap();
        assert!(!reader.is_compressed());
        let (_, expected_messages) = get_test_messages();
        for msg in expected_messages {
            assert_eq!(Ok(msg), reader.get_next_message().await.unwrap().unwrap());
        }
    }

    #[tokio::test]
    async fn test_truncation() {
        run_truncation_tests(false).await;
    }

    #[tokio::test]
    async fn test_compressed_truncation() {
        run_truncation_tests(true).await;
    }

    async fn run_truncation_tests(compressed: bool) {
        let (hdlcs, expected_messages) = get_test_messages();
        let (bytes, message_lengths): (Vec<u8>, Vec<usize>) = if compressed {
            let mut buf = Vec::new();
            let mut compressed_lengths = Vec::new();
            let mut writer = GzipEncoder::new(&mut buf);
            for hdlc in &hdlcs {
                let before = writer.get_ref().len();
                writer.write_all(&hdlc.data).await.unwrap();
                writer.flush().await.unwrap();
                let after = writer.get_ref().len();
                compressed_lengths.push(after - before);
            }
            (buf, compressed_lengths)
        } else {
            (
                get_test_message_bytes(),
                hdlcs.iter().map(|hdlc| hdlc.data.len()).collect(),
            )
        };
        for truncated_hdlc_i in 1..hdlcs.len() {
            let whole_bytes: usize = message_lengths.iter().take(truncated_hdlc_i).sum();
            for truncated_byte in 1..message_lengths[truncated_hdlc_i] {
                let mut truncated_bytes = Cursor::new(&bytes[0..whole_bytes + truncated_byte]);
                let mut reader = QmdlMessageReader::new(&mut truncated_bytes).await.unwrap();
                for msg in expected_messages.iter().take(truncated_hdlc_i) {
                    assert_eq!(
                        Ok(msg),
                        reader.get_next_message().await.unwrap().unwrap().as_ref()
                    );
                }
                if compressed {
                    // for a compressed reader, we have a couple possible
                    // outcomes, depending on how far along the Gzip DEFLATE
                    // block was before it was truncated:
                    match reader.get_next_message().await.unwrap() {
                        // if the block was truncated early enough, the
                        // GzipDecoder will detect an unexpected EOF, and our
                        // QmdlReader will indicate the stream of messages is
                        // done
                        None => {}
                        // if it's further along, the expanded result will be an
                        // invalid HDLC block. if that's the case, make sure the
                        // QmdlReader indicates the stream of messages is over
                        // with afterwards
                        Some(Err(DiagParsingError::HdlcDecapsulationError(_, _))) => {
                            assert!(matches!(reader.get_next_message().await, Ok(None)));
                        }
                        // if it's further along still, we may get a complete
                        // Message, so make sure it matches the next expected
                        // one. then, make sure we've hit the end of the message
                        // stream
                        Some(Ok(msg)) => {
                            assert_eq!(&msg, &expected_messages[truncated_hdlc_i]);
                            assert!(matches!(reader.get_next_message().await, Ok(None)));
                        }
                        // we should never be able to decapsulate the HDLC into
                        // an invalid Diag message
                        Some(Err(DiagParsingError::MessageParsingError(_, _))) => {
                            panic!("unexpected MessageParsingError");
                        }
                    }
                } else {
                    // a truncated uncompressed reader should always end on an
                    // HdlcDecapsulationError, and then return Ok(None) to
                    // indicate the message stream is over
                    assert!(matches!(
                        reader.get_next_message().await,
                        Ok(Some(Err(DiagParsingError::HdlcDecapsulationError(_, _))))
                    ));
                    assert!(matches!(reader.get_next_message().await, Ok(None)));
                }
            }
        }
    }

    /// Writes the test containers to a QmdlWriter, optionally finishing the
    /// gzip stream with a footer. Then, attempts to decompress the buffer with
    /// a QmdlWriter, asserting that the containers match what's expected.
    async fn run_compressed_reading_and_writing_tests(do_close: bool) {
        let containers = get_test_containers();
        let mut buf = Cursor::new(Vec::new());
        let writer_size = {
            let mut writer = QmdlWriter::new(&mut buf);
            for container in &containers {
                writer.write_container(container).await.unwrap();
            }
            if do_close {
                writer.close().await.unwrap()
            } else {
                writer.size().await.unwrap()
            }
        };
        assert_eq!(buf.position() as usize, writer_size);
        buf.set_position(0);
        let mut reader = QmdlMessageReader::new(buf).await.unwrap();
        assert!(reader.is_compressed());
        let (_, expected_messages) = get_test_messages();
        for message in expected_messages {
            assert_eq!(
                Ok(message),
                reader.get_next_message().await.unwrap().unwrap()
            );
        }
        assert!(matches!(reader.get_next_message().await, Ok(None)));
    }

    #[tokio::test]
    async fn test_compressed_reading_and_writing() {
        run_compressed_reading_and_writing_tests(true).await;
        run_compressed_reading_and_writing_tests(false).await;
    }

    /// An AsyncRead of `len` bytes of 0x41 (never a terminator) that counts
    /// how many bytes have been pulled out of it.
    struct CountingReader {
        remaining: usize,
        pulled: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AsyncRead for CountingReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let n = self.remaining.min(buf.remaining());
            buf.put_slice(&vec![0x41; n]);
            self.remaining -= n;
            self.pulled
                .fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncSeek for CountingReader {
        fn start_seek(self: Pin<&mut Self>, _: std::io::SeekFrom) -> std::io::Result<()> {
            Ok(())
        }
        fn poll_complete(
            self: Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> Poll<std::io::Result<u64>> {
            Poll::Ready(Ok(0))
        }
    }

    #[tokio::test]
    async fn test_max_frame_bounds_memory() {
        let pulled = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let src = CountingReader {
            remaining: 1 << 20,
            pulled: pulled.clone(),
        };
        let mut reader = QmdlMessageReader::new(src)
            .await
            .unwrap()
            .with_max_frame(16);
        let err = reader.get_next_message().await.unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(err.to_string().contains("frame exceeds limit"));
        // the BufReader's own buffer (8 KiB) is the most that may be read ahead
        let p = pulled.load(std::sync::atomic::Ordering::SeqCst);
        assert!(p <= 16 * 1024, "pulled {p} bytes before erroring");
    }

    #[tokio::test]
    async fn test_max_frame_allows_frames_within_limit() {
        let bytes = get_test_message_bytes();
        let longest = bytes
            .split_inclusive(|b| *b == MESSAGE_TERMINATOR)
            .map(|f| f.len())
            .max()
            .unwrap();
        let mut buf = Cursor::new(bytes);
        let mut reader = QmdlMessageReader::new(&mut buf)
            .await
            .unwrap()
            .with_max_frame(longest);
        let (_, expected) = get_test_messages();
        for msg in expected {
            assert_eq!(Ok(msg), reader.get_next_message().await.unwrap().unwrap());
        }
        assert!(reader.get_next_message().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn test_max_frame_one_too_small_errors() {
        let bytes = get_test_message_bytes();
        let longest = bytes
            .split_inclusive(|b| *b == MESSAGE_TERMINATOR)
            .map(|f| f.len())
            .max()
            .unwrap();
        let mut buf = Cursor::new(bytes);
        let mut reader = QmdlMessageReader::new(&mut buf)
            .await
            .unwrap()
            .with_max_frame(longest - 1);
        let mut saw_err = false;
        loop {
            match reader.get_next_message().await {
                Err(e) => {
                    assert_eq!(e.kind(), ErrorKind::InvalidData);
                    saw_err = true;
                    break;
                }
                Ok(None) => break,
                Ok(Some(_)) => {}
            }
        }
        assert!(saw_err);
    }
}
