#[derive(Clone, Copy)]
pub struct FiveTuple {
    pub protocol: L4Protocol,
    pub src: Address,
    pub dst: Address,
}

#[derive(Clone, Copy)]
pub enum L4Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Copy)]
pub struct Address {
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Clone, Copy)]
pub enum IpAddr {
    Ipv4(u32),
    Ipv6(u128),
}
impl IpAddr {
    pub fn from_ascii(b: &[u8]) -> Option<Self> {
        let mut parser = IpParser::new(b);
        parser.read_ip_addr()
    }
}

trait ReadNumberHelper: Sized {
    const ZERO: Self;
    fn checked_mul(&self, other: u32) -> Option<Self>;
    fn checked_add(&self, other: u32) -> Option<Self>;
}

macro_rules! impl_helper {
    ($($t:ty)*) => ($(impl ReadNumberHelper for $t {
        const ZERO: Self = 0;
        #[inline]
        fn checked_mul(&self, other: u32) -> Option<Self> {
            Self::checked_mul(*self, other.try_into().ok()?)
        }
        #[inline]
        fn checked_add(&self, other: u32) -> Option<Self> {
            Self::checked_add(*self, other.try_into().ok()?)
        }
    })*)
}

impl_helper! { u8 u16 u32 }

/// Basically [`core::net::parser::Parser`]
struct IpParser<'a> {
    // Parsing as ASCII, so can use byte array.
    state: &'a [u8],
}
impl<'a> IpParser<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { state: input }
    }
}
impl IpParser<'_> {
    /// Peek the next character from the input
    fn peek_char(&self) -> Option<char> {
        self.state.first().map(|&b| char::from(b))
    }

    /// Read the next character from the input
    fn read_char(&mut self) -> Option<char> {
        self.state.split_first().map(|(&b, tail)| {
            self.state = tail;
            char::from(b)
        })
    }

    #[must_use]
    /// Read the next character from the input if it matches the target.
    fn read_given_char(&mut self, target: char) -> Option<()> {
        self.read_char()
            .and_then(|c| if c == target { Some(()) } else { None })
    }

    /// Helper for reading separators in an indexed loop. Reads the separator
    /// character iff index > 0, then runs the parser. When used in a loop,
    /// the separator character will only be read on index > 0 (see
    /// read_ipv4_addr for an example)
    fn read_separator<T, F>(&mut self, sep: char, index: usize, inner: F) -> Option<T>
    where
        F: FnOnce(&mut Self) -> Option<T>,
    {
        if index > 0 {
            self.read_given_char(sep)?;
        }
        inner(self)
    }

    // Read a number off the front of the input in the given radix, stopping
    // at the first non-digit character or eof. Fails if the number has more
    // digits than max_digits or if there is no number.
    fn read_number<T: ReadNumberHelper>(
        &mut self,
        radix: u32,
        max_digits: Option<usize>,
        allow_zero_prefix: bool,
    ) -> Option<T> {
        let mut result = T::ZERO;
        let mut digit_count = 0;
        let has_leading_zero = self.peek_char() == Some('0');

        while let Some(digit) = self.read_char()?.to_digit(radix) {
            result = result.checked_mul(radix)?;
            result = result.checked_add(digit)?;
            digit_count += 1;
            if let Some(max_digits) = max_digits {
                if digit_count > max_digits {
                    return None;
                }
            }
        }

        #[allow(clippy::if_same_then_else)]
        if digit_count == 0 {
            None
        } else if !allow_zero_prefix && has_leading_zero && digit_count > 1 {
            None
        } else {
            Some(result)
        }
    }

    /// Read an IPv4 address.
    fn read_ipv4_addr(&mut self) -> Option<u32> {
        let mut groups = [0_u8; 4];

        for (i, slot) in groups.iter_mut().enumerate() {
            *slot = self.read_separator('.', i, |p| {
                // Disallow octal number in IP string.
                // https://tools.ietf.org/html/rfc6943#section-3.1.1
                p.read_number(10, Some(3), false)
            })?;
        }

        Some(u32::from_be_bytes(groups))
    }

    /// Read an IPv6 Address.
    fn read_ipv6_addr(&mut self) -> Option<u128> {
        /// Read a chunk of an IPv6 address into `groups`. Returns the number
        /// of groups read, along with a bool indicating if an embedded
        /// trailing IPv4 address was read. Specifically, read a series of
        /// colon-separated IPv6 groups (0x0000 - 0xFFFF), with an optional
        /// trailing embedded IPv4 address.
        fn read_groups(p: &mut IpParser<'_>, groups: &mut [u16]) -> (usize, bool) {
            let limit = groups.len();

            for (i, slot) in groups.iter_mut().enumerate() {
                // Try to read a trailing embedded IPv4 address. There must be
                // at least two groups left.
                if i < limit - 1 {
                    let ipv4 = p.read_separator(':', i, |p| p.read_ipv4_addr());

                    #[allow(clippy::identity_op)]
                    if let Some(v4_addr) = ipv4 {
                        let [one, two, three, four] = v4_addr.to_be_bytes();
                        groups[i + 0] = u16::from_be_bytes([one, two]);
                        groups[i + 1] = u16::from_be_bytes([three, four]);
                        return (i + 2, true);
                    }
                }

                let group = p.read_separator(':', i, |p| p.read_number(16, Some(4), true));

                match group {
                    Some(g) => *slot = g,
                    None => return (i, false),
                }
            }
            (groups.len(), false)
        }

        fn ipv6_from_u16_array(a: [u16; 8]) -> u128 {
            let mut bytes = [0_u8; 16];
            a.into_iter()
                .flat_map(|n| n.to_be_bytes())
                .enumerate()
                .for_each(|(i, b)| bytes[i] = b);
            u128::from_be_bytes(bytes)
        }

        // Read the front part of the address; either the whole thing, or up
        // to the first ::
        let mut head = [0; 8];
        let (head_size, head_ipv4) = read_groups(self, &mut head);

        if head_size == 8 {
            return Some(ipv6_from_u16_array(head));
        }

        // IPv4 part is not allowed before `::`
        if head_ipv4 {
            return None;
        }

        // Read `::` if previous code parsed less than 8 groups.
        // `::` indicates one or more groups of 16 bits of zeros.
        self.read_given_char(':')?;
        self.read_given_char(':')?;

        // Read the back part of the address. The :: must contain at least one
        // set of zeroes, so our max length is 7.
        let mut tail = [0; 7];
        let limit = 8 - (head_size + 1);
        let (tail_size, _) = read_groups(self, &mut tail[..limit]);

        // Concat the head and tail of the IP address
        head[(8 - tail_size)..8].copy_from_slice(&tail[..tail_size]);

        Some(ipv6_from_u16_array(head))
    }

    /// Read an IP Address, either IPv4 or IPv6.
    fn read_ip_addr(&mut self) -> Option<IpAddr> {
        self.read_ipv4_addr()
            .map(IpAddr::Ipv4)
            .or_else(move || self.read_ipv6_addr().map(IpAddr::Ipv6))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ascii() {
        let ip = "1.1.1.1";
        IpAddr::from_ascii(ip.as_bytes()).unwrap();
    }
}
