use crate::utils::{CursoredBuffer, ExtendableFromSlice, VecAsReadBufExt};
use bytes::BufMut;
use std::ops::Deref;
use tokio::io::ReadBuf;

#[cfg_attr(feature = "udp_info", derive(Debug))]
pub struct UdpRelayBuffer {
    cursor: usize,
    inner: Vec<u8>,
}

impl<'a> UdpRelayBuffer {
    pub fn new() -> Self {
        let buf = Vec::with_capacity(0x4000);
        Self {
            cursor: 0,
            inner: buf,
        }
    }

    pub fn as_read_buf(&'a mut self) -> ReadBuf<'a> {
        self.inner.as_read_buf()
    }

    pub unsafe fn advance_mut(&mut self, cnt: usize) {
        self.inner.advance_mut(cnt);
    }

    pub unsafe fn reset(&mut self) {
        self.inner.set_len(0);
        self.cursor = 0;
    }

    pub fn has_remaining(&self) -> bool {
        self.cursor < self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.inner.capacity() == self.inner.len()
    }

    pub fn compact(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let data_len = self.remaining();
        for i in 0..data_len {
            self.inner[i] = self.inner[i + self.cursor];
        }
        unsafe {
            self.inner.set_len(data_len);
        }
        self.cursor = 0;
    }

    pub fn reserve_by_cursor(&mut self, len: usize) {
        if len + self.cursor <= self.inner.capacity() {
            return;
        }
        let mut new_inner = Vec::with_capacity(len);
        new_inner.extend_from_slice(self.chunk());
        self.inner = new_inner;
        self.cursor = 0;
    }
}

impl<'a> CursoredBuffer for UdpRelayBuffer {
    fn chunk(&self) -> &[u8] {
        &self.inner[self.cursor..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.inner.len() >= self.cursor + len,
            "UdpRelayBuffer was about to set a larger position({}+{}) than it's length({})",
            self.cursor,
            len,
            self.inner.len()
        );
        self.cursor += len;
    }
}

impl Deref for UdpRelayBuffer {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.chunk()
    }
}

impl ExtendableFromSlice for UdpRelayBuffer {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.inner.extend_from_slice(src);
    }
}
