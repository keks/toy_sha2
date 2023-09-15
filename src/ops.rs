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
