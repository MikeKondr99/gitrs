use std::{
    array::TryFromSliceError, fmt::Display,
};

struct Sha1([u8; 20]);

impl TryFrom<&[u8]> for Sha1 {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        value.try_into().map(Sha1)
    }
}

impl TryFrom<&str> for Sha1 {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        const l: &str = "0123456789ABCDEFG";
        let mut bytes = [0u8; 20];
        for (i, (a, b)) in value
            .chars()
            .step_by(2)
            .zip(value.chars().skip(1).step_by(2))
            .enumerate()
        {
            let a = l.find(a).ok_or(())? as u8;
            let b = l.find(b).ok_or(())? as u8;
            bytes[i] = a << 4 | b;
        }
        Ok(Sha1(bytes))
    }
}

impl Sha1 {

    pub fn encode(data: &[u8]) -> Sha1 {
        let len = if data.len() % 64 > 55 {
            (data.len() / 64 + 2) * 64
        } else {
            (data.len() / 64 + 1) * 64
        };
        let mut h:[u32;5] = [ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 ]; // магические числа
        let mut vec = vec![0u8; len];
        assert_eq!(vec.len() % 64,0);
        vec[..data.len()].clone_from_slice(data); // <message>00...00
        vec[data.len()] = 0x80; // <message>100.00
        vec[len - 8..].clone_from_slice(&(data.len() as u64).to_be_bytes()); // <message>100..00<message.len as u64>
        println!("{vec:02X?}");
        for chunk in vec.chunks(64).map(|c| 
            c.chunks(4).map(|x| u32::from_be_bytes(x.try_into().unwrap()))
        ) {
            let mut w = [0u32; 80];
            for (i, c) in chunk.enumerate() { // заполняем первые 16 кусочков
                debug_assert_ne!(i, 16);
                w[i] = c;
            }
            for i in 16..80 { //заполняем остальные
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1); 
            }
            println!("{w:08X?}");
            let mut v = h; // копируем
            for (i,w) in w.iter().enumerate() {
                let [a,b, c, d,e] = v; // aliases
                let (f, k):(u32,u32) = match i {
                    00..=19 => (b & c | !b & d       , 0x5A827999),
                    20..=39 => (b ^ c ^ d            , 0x6ED9EBA1),
                    40..=59 => (b & c | b & d | c & d, 0x8F1BBCDC),
                    60..=79 => (b ^ c ^ d            , 0xCA62C1D6),
                    _ => unreachable!(),
                };
                v = [
                    a.rotate_left(5).overflowing_add(f).0.overflowing_add(e).0.overflowing_add(k).0.overflowing_add(*w).0,
                    a,
                    b.rotate_left(30),
                    c,
                    d,
                ];
                h.iter_mut().zip(v).for_each(|(h,v)| *h = h.overflowing_add(v).0);
            }
        }
        let res:Vec<u8> = h.map(|x| x.to_be_bytes()).into_iter().flatten().collect();
        res[..].try_into().unwrap()
    }
}

impl Display for Sha1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for data in self.0 {
            write!(f, "{data:02X}").unwrap();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::{assert_eq, assert_ne};
    use rstest::rstest;

    #[rstest]

    fn try_from_bytes_slice() {
        let sha: Sha1 = "abcdefghijklmnopqrstuvwxyz".as_bytes()[0..20]
            .try_into()
            .unwrap();
    }

    #[rstest]
    #[case("68695759657552474D5749715042386666686330")]
    #[case("4579667A62774254505448704B76705A70753643")]
    #[case("57337965544462306D52776E6C55367475614E66")]
    #[case("6134394451474441414443316644303047457230")]
    #[case("4D50424C4D775834556A6F7143416F6E4D705739")]
    #[case("7564476735476F6D6839633464374D36344E7A47")]
    #[case("566730544874635342455671626C304F6A337661")]
    #[case("677673654442596B694B5A76747347503249624D")]
    #[case("69626F7A4658474B71384F7938667A7A4C474133")]
    fn try_from_string(#[case] s: &str) {
        let sha: Sha1 = s.try_into().unwrap();
        assert_eq!(format!("{sha}"), s);
    }

    #[rstest]
    #[case("hiWYeuRGMWIqPB8ffhc0", "68695759657552474D5749715042386666686330")]
    #[case("EyfzbwBTPTHpKvpZpu6C", "4579667A62774254505448704B76705A70753643")]
    #[case("W3yeTDb0mRwnlU6tuaNf", "57337965544462306D52776E6C55367475614E66")]
    #[case("a49DQGDAADC1fD00GEr0", "6134394451474441414443316644303047457230")]
    #[case("MPBLMwX4UjoqCAonMpW9", "4D50424C4D775834556A6F7143416F6E4D705739")]
    #[case("udGg5Gomh9c4d7M64NzG", "7564476735476F6D6839633464374D36344E7A47")]
    #[case("Vg0THtcSBEVqbl0Oj3va", "566730544874635342455671626C304F6A337661")]
    #[case("gvseDBYkiKZvtsGP2IbM", "677673654442596B694B5A76747347503249624D")]
    #[case("ibozFXGKq8Oy8fzzLGA3", "69626F7A4658474B71384F7938667A7A4C474133")]
    fn display(#[case] str: &str, #[case] expected: &str) {
        let sha: Sha1 = str.as_bytes()[0..20].try_into().unwrap();
        assert_eq!(format!("{sha}"), expected);
    }

    #[rstest]
    #[case("hello world", "2AAE6C35C94FCFB415DBE95F408B9CE91EE846ED")]
    fn encode(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(format!("{}", Sha1::encode(input.as_bytes())), expected)
    }
}
