#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessKind {
    Unknown,
    Read,
    Write,
    Execute,
    Recursion,
}

impl AccessKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Read => "read",
            Self::Write => "write",
            Self::Execute => "exec",
            Self::Recursion => "recursion",
        }
    }
}

pub fn classify(instruction: u32) -> AccessKind {
    if instruction & 0x3f00_0000 == 0x0800_0000 {
        return load_bit(instruction);
    }
    if instruction & 0x3b00_0000 == 0x1800_0000 {
        return AccessKind::Read;
    }
    if instruction & 0x3a00_0000 == 0x2800_0000 {
        return load_bit(instruction);
    }
    if instruction & 0x3a00_0000 == 0x3800_0000 {
        return load_bit(instruction);
    }
    if matches!(instruction & 0xbf00_0000, 0x0c00_0000 | 0x0d00_0000) {
        return load_bit(instruction);
    }
    if matches!(instruction & 0xffff_fc1f, 0xd61f_0000 | 0xd63f_0000) {
        return AccessKind::Execute;
    }
    AccessKind::Unknown
}

fn load_bit(instruction: u32) -> AccessKind {
    if instruction & (1 << 22) == 0 {
        AccessKind::Write
    } else {
        AccessKind::Read
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_representative_instructions() {
        let cases = [
            (0xf900_0020, AccessKind::Write),
            (0xf940_0020, AccessKind::Read),
            (0xa900_0440, AccessKind::Write),
            (0xa940_0440, AccessKind::Read),
            (0xc800_7c41, AccessKind::Write),
            (0xc85f_7c41, AccessKind::Read),
            (0x4c00_7020, AccessKind::Write),
            (0x4c40_7020, AccessKind::Read),
            (0xd61f_0000, AccessKind::Execute),
            (0x9100_0400, AccessKind::Unknown),
        ];
        for (instruction, expected) in cases {
            assert_eq!(classify(instruction), expected);
        }
    }
}
