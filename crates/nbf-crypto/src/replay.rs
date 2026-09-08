//! Lọc replay đơn giản: seq phải tăng đơn điệu theo từng (circuit, chiều) tại mỗi hop.
//! Nới lỏng: chấp nhận nhảy số (không yêu cầu cửa sổ trượt) — v1 đủ cho localhost/LAN;
//! v2 thay bằng ring-window chống out-of-order thật.

#[derive(Debug)]
pub struct MonotonicCheck {
    last: u32,
}

impl MonotonicCheck {
    pub fn new() -> Self {
        Self { last: 0 }
    }

    /// true = chấp nhận (seq > last, cập nhật last); false = replay/cũ.
    pub fn check(&mut self, seq: u32) -> bool {
        if seq <= self.last {
            return false;
        }
        self.last = seq;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chong_replay() {
        let mut m = MonotonicCheck::new();
        assert!(m.check(7));
        assert!(!m.check(7));
        assert!(m.check(8));
        assert!(!m.check(0));
    }
}
