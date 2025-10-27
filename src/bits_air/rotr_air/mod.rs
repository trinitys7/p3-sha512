use p3_air::AirBuilder;
use p3_field::{PrimeField32, PrimeCharacteristicRing};

use crate::constants::U32_LIMBS;

#[derive(Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct RightRotateAir<T> {
    /// The output value.
    pub value: [T; U32_LIMBS],
  
    /// The c_mod == 0 condition of `shrcarry` on each byte of a word.
    pub c_mod_is_zero: [T; U32_LIMBS],

    /// b << (8 - c_mod) of `shrcarry` on each byte of a word.
    pub left_aligned_carry: [T; U32_LIMBS],

    /// The shift output of `shrcarry` on each byte of a word.
    pub shift: [T; U32_LIMBS],

    /// The carry ouytput of `shrcarry` on each byte of a word.
    pub carry: [T; U32_LIMBS],
}


impl<F: PrimeField32> RightRotateAir<F> {
     pub const fn nb_bytes_to_shift(rotation: usize) -> usize {
        rotation / 8
    }

    pub const fn nb_bits_to_shift(rotation: usize) -> usize {
        rotation % 8
    }

    pub const fn carry_multiplier(rotation: usize) -> u32 {
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        1 << (8 - nb_bits_to_shift)
    }


    pub fn populate(
        &mut self,
        input: u32,
        rotation: usize,
    ) -> u32 {
        let input_bytes = input.to_le_bytes().map(F::from_u8);
        let expected = input.rotate_right(rotation as u32);

        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = F::from_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated: [F; 4] = [
            input_bytes[nb_bytes_to_shift % U32_LIMBS],
            input_bytes[(1 + nb_bytes_to_shift) % U32_LIMBS],
            input_bytes[(2 + nb_bytes_to_shift) % U32_LIMBS],
            input_bytes[(3 + nb_bytes_to_shift) % U32_LIMBS],
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = F::ZERO;
        let mut last_carry = F::ZERO;
        for i in (0..U32_LIMBS).rev() {
            let b = input_bytes_rotated[i].to_string().parse::<u8>().unwrap();
            let c = nb_bits_to_shift as u8;

            let (shift, carry) = {
                let c_mod = c & 0x7;
                if c_mod != 0 {
                    let res = b >> c_mod;
                    let carry = (b << (8 - c_mod)) >> (8 - c_mod);
                    self.c_mod_is_zero[i] = F::ONE;
                    self.left_aligned_carry[i] = F::from_u8(b << (8 - c_mod));
                    (res, carry)
                } else {
                    self.c_mod_is_zero[i] = F::ZERO;
                    (b, 0u8)
                }
            };
            self.shift[i] = F::from_u8(shift);
            self.carry[i] = F::from_u8(carry);

            if i == U32_LIMBS - 1 {
                first_shift = self.shift[i];
            } else {
                self.value[i] = self.shift[i] + last_carry * carry_multiplier;
            }

            last_carry = self.carry[i];
        }

        // For the first byte, we didn't know the last carry so compute the rotated byte here.
        self.value[U32_LIMBS - 1] = first_shift + last_carry * carry_multiplier;

        // Check that the value is correct.
        assert_eq!(u32::from_le_bytes(self.value.map(|x| x.to_string().parse::<u8>().unwrap())), expected);

        expected
    }


    pub fn eval<AB: AirBuilder>(
        builder: &mut AB,
        input: [AB::Var; U32_LIMBS],
        rotation: usize,
        cols: RightRotateAir<AB::Var>,
    ) {
        // Compute some constants with respect to the rotation needed for the rotation.
        let nb_bytes_to_shift = Self::nb_bytes_to_shift(rotation);
        let nb_bits_to_shift = Self::nb_bits_to_shift(rotation);
        let carry_multiplier = AB::F::from_u32(Self::carry_multiplier(rotation));

        // Perform the byte shift.
        let input_bytes_rotated = [
            input[nb_bytes_to_shift % U32_LIMBS].clone(),
            input[(1 + nb_bytes_to_shift) % U32_LIMBS].clone(),
            input[(2 + nb_bytes_to_shift) % U32_LIMBS].clone(),
            input[(3 + nb_bytes_to_shift) % U32_LIMBS].clone(),
        ];

        // For each byte, calculate the shift and carry. If it's not the first byte, calculate the
        // new byte value using the current shifted byte and the last carry.
        let mut first_shift = AB::Expr::ZERO;
        let mut last_carry = AB::Expr::ZERO;
        for i in (0..U32_LIMBS).rev() {
            // TODO: assert shift right carry
            let c_mod = (nb_bits_to_shift & 0x07) as u8;

            let c_mod_not_zero = AB::Expr::ONE - cols.c_mod_is_zero[i].clone();
            // assert when c_mod is zero
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(AB::F::from_u8(c_mod));
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_eq(input_bytes_rotated[i].clone(), cols.shift[i].clone());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_eq(AB::Expr::ZERO, cols.carry[i].clone());

            // assert when c_mod is not zero
            let left_shift_amount =  8 - c_mod;
            builder
                .when(c_mod_not_zero.clone())
                .assert_eq(cols.shift[i].clone(), input_bytes_rotated[i].clone().into().div_2exp_u64(c_mod as u64));
            builder
                .when(c_mod_not_zero.clone())
                .assert_eq(cols.left_aligned_carry[i].clone(),input_bytes_rotated[i].clone().into().mul_2exp_u64(left_shift_amount as u64));
            builder
                .when(c_mod_not_zero)
                .assert_eq(cols.carry[i].clone(),cols.left_aligned_carry[i].clone().into().div_2exp_u64(left_shift_amount as u64));

            // assert when c_mod is zero
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_eq(cols.shift[i].clone(), input_bytes_rotated[i].clone().into());
            builder
                .when(cols.c_mod_is_zero[i].clone())
                .assert_zero(cols.carry[i].clone());

            if i == U32_LIMBS - 1 {
                first_shift = cols.shift[i].clone().into();
            } else {
                builder.assert_eq(cols.value[i].clone(), cols.shift[i].clone() + last_carry * carry_multiplier.clone());
            }

            last_carry = cols.carry[i].clone().into();
        }

        // For the first byte, we didn't know the last carry so compute the rotated byte here.
        builder.assert_eq(
            cols.value[U32_LIMBS - 1].clone(),
            first_shift + last_carry * carry_multiplier,
        );
    }
}


pub const fn shr_carry(input: u8, rotation: u8) -> (u8, u8) {
    let c_mod = rotation & 0x7;
    if c_mod != 0 {
        let res = input >> c_mod;
        let carry = (input << (8 - c_mod)) >> (8 - c_mod);
        (res, carry)
    } else {
        (input, 0u8)
    }
}
