const SNINAME_TYPE_DNS: u8 = 0;
const EXT_SERVER_NAME: u16 = 0;

#[derive(Default)]
struct TLSMessage {
    msg_type: u8,
}

const CLIENT_HELLO_RANDOM_LEN: usize = 32;

#[derive(Default)]
struct ClientHello {
    message: TLSMessage,
    handshake_type: u8,
    sessionid_len: u32,
    cipersuite_len: u16,
    extension_len: u16,
    sni: String,
}

pub fn parse_sni(payload: &[u8]) -> Option<String> {
    let mut ch = ClientHello::default();
    ch.message.msg_type = payload[0];

    if ch.message.msg_type != 22 {
        return None;
    }

    let hs = &payload[5..];
    if hs.len() < 6 {
        return None;
    }

    ch.handshake_type = hs[0];
    if ch.handshake_type != 1 {
        return None;
    }

    let hs = &hs[6..];
    if hs.len() < CLIENT_HELLO_RANDOM_LEN {
        return None;
    }

    let hs = &hs[CLIENT_HELLO_RANDOM_LEN..];
    if hs.len() < 1 {
        return None;
    }

    // Get SessionID
    ch.sessionid_len = hs[0] as u32;

    let hs = &hs[1..];
    if hs.len() < ch.sessionid_len as usize {
        return None;
    }

    let hs = &hs[ch.sessionid_len as usize..];
    if hs.len() < 2 {
        return None;
    }

    // Cipher Suite
    ch.cipersuite_len = (hs[0] as u16) << 8 | hs[1] as u16;
    if hs.len() < ch.cipersuite_len as usize {
        return None;
    }

    let hs = &hs[2 + ch.cipersuite_len as usize..];
    if hs.len() < 1 {
        return None;
    }

    // Compression Methods
    let num_compress_methods = hs[0];

    if hs.len() < 1 + num_compress_methods as usize {
        return None;
    }

    let hs = &hs[1 + num_compress_methods as usize..];
    if hs.len() < 2 {
        // No extensions or malformed length
        return None;
    }

    // Extensions
    ch.extension_len = (hs[0] as u16) << 8 | hs[1] as u16;
    if hs.len() < ch.extension_len as usize {
        return None;
    }

    let hs = &hs[2..];

    while hs.len() > 0 {
        if hs.len() < 4 {
            return None;
        }

        let ext_type = (hs[0] as u16) << 8 | hs[1] as u16;
        let length = (hs[2] as u16) << 8 | hs[3] as u16;

        if hs.len() < 4 + length as usize {
            return None;
        }

        let data = &hs[4..4 + length as usize];

        if ext_type == EXT_SERVER_NAME {
            if data.len() < 2 {
                return None;
            }
            let sni_len = (data[0] as u16) << 8 | data[0] as u16;

            let mut data = &data[2..];

            if data.len() < sni_len as usize {
                // Malformed SNI data
                return None;
            }

            loop {
                if data.len() <= 0 {
                    break;
                }
                let name_type = data[0];
                if data.len() < 3 {
                    // Malformed ServerName
                    return None;
                }

                let name_len = (data[1] as u16) << 8 | data[2] as u16;
                data = &data[3..];

                if name_type == SNINAME_TYPE_DNS {
                    ch.sni = std::str::from_utf8(data).unwrap().to_string();
                    return Some(ch.sni);
                }
                data = &data[name_len as usize..];
            }
        }
    }
    return None;
}
