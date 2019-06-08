pub const CONNECTION_TOKEN: mio::Token = mio::Token(0);
pub const READLINE_TOKEN: mio::Token = mio::Token(1);
pub const REMOTE_CONTROL_TOKEN: mio::Token = mio::Token(2);
pub const CATEGORY_BASE: usize = 0x00000000;
#[deny(overflowing_literals)]
pub const CATEGORY_PORTFWD_BIND: usize = 0x01000000;
pub const CATEGORY_PORTFWD_ACCEPT: usize = 0x02000000;
pub const CATEGORY_PORTFWD_CONNECT: usize = 0x03000000;
