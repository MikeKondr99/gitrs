use std::{array::TryFromSliceError, fmt::Display};

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
    pub fn encode(message: &[u8]) -> Sha1 {
        let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]; // магические числа
        for block in Sha1::prepare_blocks(message) {
            Sha1::print_block("block", &block);

            let mut w = [0u32; 80];
            w[..16].copy_from_slice(&block.map(|x| u32::from_be_bytes(x.to_be_bytes())));
            for i in 16..80 {
                w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
            }
            for (i, w) in w.array_chunks::<16>().enumerate() {
                Sha1::print_block(&format!("w[{}..{}", i * 16, i * 16 + 16), w);
            }
            println!("w: {w:08X?}");
            let mut v = h; // копируем
            println!("{h:08X?}");
            for t in 0..80 {
                let [_, b, c, d, _] = v; // aliases
                let fk = Sha1::fk(t, b, c, d);
                Sha1::transmute(&mut v, fk, w[t]);
                h.iter_mut()
                    .zip(v)
                    .for_each(|(h, v)| *h = h.wrapping_add(v));
                println!("{h:08X?}")
            }
        }
        println!("h: {h:08X?}");
        let res: Vec<u8> = h.map(|x| x.to_be_bytes()).into_iter().flatten().collect();
        res[..].try_into().unwrap()
    }

    fn prepare_blocks(message: &[u8]) -> Vec<[u32; 16]> {
        // returns vec of SHA1 BLOCKS
        let n = if message.len() % 64 > 55 { 2 } else { 1 };
        let len = (message.len() / 64 + n) * 64; // длина либо расширяется на 512 либо нет
        let mut vec = Vec::with_capacity(len / 32); // выделяем память под блоки
        assert_eq!(vec.len() % 16, 0); // должно быть кратно 512 бит
        let (data, rem) = message.as_chunks::<4>();
        vec.extend(data.iter().map(|x| u32::from_be_bytes(*x)));
        if !rem.is_empty() {
            let mut a = [0u8; 4];
            a[0..rem.len()].copy_from_slice(rem);
            a[rem.len()] = 0x80;
            vec.push(u32::from_be_bytes(a));
        } else {
            vec.push(0x80000000);
        }
        vec.resize(14, 0);
        let size: u64 = (message.len() as u64) * 8;
        vec.push((size << 32) as u32);
        vec.push(size as u32);
        assert_eq!(vec.len() % 16, 0);
        vec.array_chunks::<16>().cloned().collect()
    }

    fn print_block(name: &str, block: &[u32; 16]) {
        println!("{name}");
        for i in (0..16).step_by(4) {
            println!(
                "{:08X} {:08X} {:08X} {:08X}",
                block[i],
                block[i + 1],
                block[i + 2],
                block[i + 3]
            )
        }
        println!();
    }

    fn transmute(v: &mut [u32; 5], fk: u32, wt: u32) {
        let new = [
            v[0].rotate_left(5)
                .wrapping_add(fk)
                .wrapping_add(v[4])
                .wrapping_add(wt),
            v[0],
            v[1].rotate_left(30),
            v[2],
            v[3],
        ];
        println!("tra({v:08X?},{fk:08X},{wt:08X}) => {new:08X?}");
        v.iter_mut().zip(new).for_each(|(v, n)| *v = n);
    }

    fn fk(t: usize, b: u32, c: u32, d: u32) -> u32 {
        let (f,k) = match t {
            00..=19 => (b & c | !b & d, 0x5A827999),
            20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
            40..=59 => (b & c | b & d | c & d, 0x8F1BBCDC),
            60..=79 => (b ^ c ^ d, 0xCA62C1D6),
            _ => unreachable!(),
        };
        println!("fk({t:08X},{b:08X},{c:08X},{d:08X}) => {f:08X} + {k:08X}");
        u32::wrapping_add(f, k)
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
    fn try_from_string(#[case] s: &str) {
        let sha: Sha1 = s.try_into().unwrap();
        assert_eq!(format!("{sha}"), s);
    }

    #[rstest]
    #[case("hiWYeuRGMWIqPB8ffhc0", "68695759657552474D5749715042386666686330")]
    #[case("EyfzbwBTPTHpKvpZpu6C", "4579667A62774254505448704B76705A70753643")]
    #[case("W3yeTDb0mRwnlU6tuaNf", "57337965544462306D52776E6C55367475614E66")]
    #[case("a49DQGDAADC1fD00GEr0", "6134394451474441414443316644303047457230")]
    fn display(#[case] str: &str, #[case] expected: &str) {
        let sha: Sha1 = str.as_bytes()[0..20].try_into().unwrap();
        assert_eq!(format!("{sha}"), expected);
    }

    #[rstest]
    #[case("abcde", "03DE6C570BFE24BFC328CCD7CA46B76EADAF4334")]
    fn encode(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(format!("{}", Sha1::encode(input.as_bytes())), expected)
    }

    #[rstest]
    #[case(10, 0x26EA74BC, 0xCD0AF957, 0xB30B23C9, 0xEF8DECEE)]
    #[case(30, 0x353A2010, 0xA835EC3A, 0xD1C4D076, 0xBBA507FD)]
    #[case(50, 0x90236E48, 0xB83C0990, 0xD9658F02, 0x2740CBDC)]
    #[case(70, 0x4F5D1322, 0xDB469DA0, 0x97A4BD58, 0xCE21F5B0)]
    fn fk(#[case] t: usize, #[case] b: u32, #[case] c: u32, #[case] d: u32, #[case] expected: u32) {
        println!("b: {b:02X} c: {c:02X} d: {d:02X}");
        let res = Sha1::fk(t,b,c,d);

        assert_eq!(res, expected);
    }

    #[rstest]
    #[case(0x61626364, 0xCD0AF957,
        [0xA82CA0B2, 0x37D62331, 0x9E21D818, 0xDA4C5411, 0x785E6B9C],
        [0xAC5FDEAC, 0xA82CA0B2, 0x4DF588CC, 0x9E21D818, 0xDA4C5411]
    )]
    fn transmute( #[case] fk: u32, #[case] wt: u32,#[case] mut v: [u32; 5],#[case] expected: [u32; 5]) {

        Sha1::transmute(&mut v, fk, wt);

        assert_eq!(v, expected);
    }
}
