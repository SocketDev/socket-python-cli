use smallvec::SmallVec;

fn main() {
    let mut values: SmallVec<[u8; 4]> = SmallVec::new();
    values.insert_many(0, vec![1, 2, 3]);
    println!("{:?}", values);
}
