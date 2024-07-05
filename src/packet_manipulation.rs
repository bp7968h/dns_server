use std::error::Error;

pub struct BytePacketBuffer {
    pub buf: [u8; 512],
    pub pos: usize
}

impl BytePacketBuffer {
    // buffer to hold packets as DNS is 512 bytes
    pub fn new() -> BytePacketBuffer {
        BytePacketBuffer {
            buf: [0; 512],
            pos: 0
        }
    }

    // current position of packet in buffer
    fn pos(&self) -> usize {
        self.pos
    }

    // shift buffer position
    pub fn step(&mut self, steps: usize) -> std::result::Result<(),Box<dyn Error>> {
        self.pos += steps;

        Ok(())
    }

    /// Change the buffer position
    fn seek(&mut self, pos: usize) -> std::result::Result<(), Box<dyn Error>> {
        self.pos = pos;

        Ok(())
    }

    // read a single byte and move ahead
    fn read(&mut self) -> Result<u8, Box<dyn Error>> {
        if self.pos >= 512 {
            return Err("End of buffer".into());
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    // Get a single byte, without changing the buffer position
    fn get(&mut self, pos: usize) -> std::result::Result<u8, Box<dyn Error>> {
        if pos >= 512 {
            return Err("End of buffer".into());
        }
        Ok(self.buf[pos])
    }

    /// Get a range of bytes
    fn get_range(&mut self, start: usize, len: usize) -> std::result::Result<&[u8], Box<dyn Error>> {
        if start + len >= 512 {
            return Err("End of buffer".into());
        }
        Ok(&self.buf[start..start + len as usize])
    }

    /// Read two bytes, stepping two steps forward
    pub fn read_u16(&mut self) -> std::result::Result<u16, Box<dyn Error>> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    /// Read four bytes, stepping four steps forward
    pub fn read_u32(&mut self) -> std::result::Result<u32, Box<dyn Error>> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }

    //Read qname from buffer
    pub fn read_qname(&mut self, outstr: &mut String) -> std::result::Result<(), Box<dyn Error>> {
        let mut pos = self.pos();

        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        let mut delim = "";
        loop{
            if jumps_performed > max_jumps {
                return Err(format!("Limit of {} jumps exceeded", max_jumps).into());
            }

            // labels start with length byte
            let len = self.get(pos)?;

            if (len & 0xC0) == 0xC0 {
                if !jumped{
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            } else {
                pos += 1;

                // labels are terminated by 0 byte if so we break out
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                outstr.push_str(delim);

                //Extract the actual ASCII bytes for this label and append them and . to outstr
                let str_buffer = self.get_range(pos, len as usize)?;
                outstr.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(())
    }
}