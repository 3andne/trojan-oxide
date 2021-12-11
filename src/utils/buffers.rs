use bytes::BufMut;
use tokio::io::ReadBuf;

pub trait CursoredBuffer {
    fn chunk(&self) -> &[u8];
    fn advance(&mut self, len: usize);
    fn remaining(&self) -> usize {
        self.chunk().len()
    }
}

impl<'a> CursoredBuffer for (&'a mut usize, &Vec<u8>) {
    fn chunk(&self) -> &[u8] {
        &self.1[*self.0..]
    }

    fn advance(&mut self, len: usize) {
        assert!(
            self.1.len() >= *self.0 + len,
            "(&'a mut usize, &Vec<u8>) was about to set a larger position than it's length"
        );
        *self.0 += len;
    }
}

pub trait VecAsReadBufExt<'a> {
    fn as_read_buf(&'a mut self) -> ReadBuf<'a>;
}

impl<'a> VecAsReadBufExt<'a> for Vec<u8> {
    fn as_read_buf(&'a mut self) -> ReadBuf<'a> {
        let dst = &mut self.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>]) };
        ReadBuf::uninit(dst)
    }
}

pub trait ExtendableFromSlice {
    fn extend_from_slice(&mut self, src: &[u8]);
}

impl ExtendableFromSlice for Vec<u8> {
    fn extend_from_slice(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}
