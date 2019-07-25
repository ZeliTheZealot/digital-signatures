pub mod fibonacci;
pub mod print_one;

pub fn add_one(x: i32) -> i32 {
    x + 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::add_one;

    #[test]
    fn test_add_one() {
        assert_eq!(add_one(3), 4);
    }
}
