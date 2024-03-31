use cipher::{inout::InOutBuf, BlockDecryptMut, BlockEncryptMut};

use crate::{Dec, Enc};

pub fn encrypt_inout(enc: &mut Enc, data: InOutBuf<'_, '_, u8>) {
    let (blocks, mut tail) = data.into_chunks();
    enc.encrypt_blocks_inout_mut(blocks);
    let n = tail.len();
    if n != 0 {
        let mut block = crypto::common::Block::<Enc>::default();
        block[..n].copy_from_slice(tail.get_in());
        enc.encrypt_block_mut(&mut block);
        tail.get_out().copy_from_slice(&block[..n]);
    }
}

pub fn decrypt_inout(dec: &mut Dec, data: InOutBuf<'_, '_, u8>) {
    let (blocks, mut tail) = data.into_chunks();
    dec.decrypt_blocks_inout_mut(blocks);
    let n = tail.len();
    if n != 0 {
        let mut block = crypto::common::Block::<Dec>::default();
        block[..n].copy_from_slice(tail.get_in());
        dec.decrypt_block_mut(&mut block);
        tail.get_out().copy_from_slice(&block[..n]);
    }
}
