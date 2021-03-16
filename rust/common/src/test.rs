use super::*;

fn test_val(val: usize) {
    let hbytes = varint_encode_len(val);
    let mut buf: [u8; 6] = [0, 0, 0, 0, 0, 0];
    assert!(hbytes == varint_encode(val, &mut buf[0..]));
    assert!((hbytes, val) == varint_decode(&buf[0..]))
}
#[test]
fn varint_test() {
    test_val(123);
    test_val(255);
    test_val(123456);
    test_val(123456789);
}
