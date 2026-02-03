use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MsgId(pub u64);

#[derive(Serialize, Deserialize, Debug)]
pub struct ChunkHeader {
    pub id: MsgId,
    pub idx: u16,
    pub total: u16,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Chunk {
    pub hdr: ChunkHeader,
    pub payload: Vec<u8>, // dati chiari PRIMA della cifratura AEAD (poi sigilliamo)
}

/// Divide dati in chunks di dimensione massima
pub fn split_chunks(id: u64, data: &[u8], max_chunk: usize) -> Vec<(ChunkHeader, Vec<u8>)> {
    let total = data.len().div_ceil(max_chunk) as u16;
    let mut v = Vec::with_capacity(total as usize);

    for (i, chunk) in data.chunks(max_chunk).enumerate() {
        v.push((
            ChunkHeader {
                id: MsgId(id),
                idx: i as u16,
                total,
            },
            chunk.to_vec(),
        ));
    }
    v
}

/// Riassembla chunks in messaggio completo
pub struct Reassembler {
    buf: BTreeMap<u16, Vec<u8>>,
    total: Option<u16>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            buf: BTreeMap::new(),
            total: None,
        }
    }

    /// Aggiunge un chunk e ritorna il messaggio completo se tutti i chunk sono arrivati
    pub fn push(&mut self, hdr: &ChunkHeader, payload: Vec<u8>) -> Option<Vec<u8>> {
        self.buf.insert(hdr.idx, payload);
        self.total.get_or_insert(hdr.total);

        if self.buf.len() == self.total.unwrap_or(0) as usize {
            let mut out = Vec::new();
            for (_, part) in self.buf.iter() {
                out.extend_from_slice(part);
            }
            return Some(out);
        }
        None
    }

    /// Controlla se il riassemblatore è completo
    pub fn is_complete(&self) -> bool {
        if let Some(total) = self.total {
            self.buf.len() == total as usize
        } else {
            false
        }
    }

    /// Resetta il riassemblatore
    pub fn clear(&mut self) {
        self.buf.clear();
        self.total = None;
    }
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chunk_split_and_reassemble() {
        let data = b"Hello, this is a test message for chunking functionality!";
        let max_chunk = 10;
        let msg_id = 12345;

        // Split in chunks
        let chunks = split_chunks(msg_id, data, max_chunk);
        assert!(chunks.len() > 1); // Dovrebbe essere diviso in più chunk

        // Reassemble
        let mut reassembler = Reassembler::new();
        let mut result = None;

        for (header, payload) in chunks {
            result = reassembler.push(&header, payload);
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap(), data.to_vec());
    }

    #[test]
    fn test_chunk_out_of_order() {
        let data = b"Out of order test message";
        let max_chunk = 5;
        let msg_id = 54321;

        let chunks = split_chunks(msg_id, data, max_chunk);
        let mut reassembler = Reassembler::new();

        // Invia chunks in ordine inverso
        let mut result = None;
        for (header, payload) in chunks.into_iter().rev() {
            result = reassembler.push(&header, payload);
        }

        assert!(result.is_some());
        assert_eq!(result.unwrap(), data.to_vec());
    }
}
