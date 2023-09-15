pub trait Rotr<Rhs = Self> {
    type Output;

    fn rotr(self, other: Rhs) -> Self::Output;
}

impl Rotr<usize> for u32 {
    type Output = u32;

    fn rotr(self, by: usize) -> u32 {
        (self >> by) | (self << (32 - by))
    }
}

impl Rotr<usize> for u64 {
    type Output = u64;

    fn rotr(self, by: usize) -> u64 {
        (self >> by) | (self << (64 - by))
    }
}
