use core::borrow::{Borrow, BorrowMut};
use core::mem::{size_of, transmute};

use p3_util::indices_arr;

use crate::constants::{NUM_ROUNDS, U32_LIMBS};

#[derive(Debug)]
#[repr(C)]
pub struct ShaCols<T> {
    pub step_flags: [T; NUM_ROUNDS],
    pub export: T,
    // pub is_round: T,
    // pub is_digest: T,
    // pub is_last_block:T,

    pub input_block: [T; 64],
    pub prev_seed: [[T; U32_LIMBS]; 8],
    pub seed: [[T; U32_LIMBS]; 8],
    pub final_hash: [[T; U32_LIMBS]; 8],
    pub extend: [[T; U32_LIMBS]; 64],
    pub buf: [[T; U32_LIMBS]; 64],
}

pub const NUM_SHA_COLS: usize = size_of::<ShaCols<u8>>();


impl<T> Borrow<ShaCols<T>> for [T] {
    fn borrow(&self) -> &ShaCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<ShaCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T> BorrowMut<ShaCols<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut ShaCols<T> {
        debug_assert_eq!(self.len(), NUM_SHA_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<ShaCols<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
