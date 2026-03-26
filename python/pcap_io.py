import struct
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class PcapPacket:
    ts_sec: int
    ts_usec: int
    data: bytes


class PcapReader:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = None
        self.packets: List[PcapPacket] = []
        self._read_all()
    
    def _read_all(self):
        with open(self.filename, 'rb') as f:
            header = f.read(24)
            if len(header) < 24:
                raise ValueError("Invalid PCAP file: header too short")
            
            magic = struct.unpack('<I', header[0:4])[0]
            if magic != 0xa1b2c3d4:
                raise ValueError(f"Invalid PCAP magic number: 0x{magic:08x}")
            
            while True:
                pkt_header = f.read(16)
                if len(pkt_header) < 16:
                    break
                
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('<IIII', pkt_header)
                data = f.read(incl_len)
                if len(data) < incl_len:
                    break
                
                self.packets.append(PcapPacket(ts_sec=ts_sec, ts_usec=ts_usec, data=data))


class PcapWriter:
    def __init__(self, filename: str):
        self.filename = filename
        self.file = open(filename, 'wb')
        header = struct.pack('<IHHiIII',
            0xa1b2c3d4,  # magic
            2,            # version major
            4,            # version minor
            0,            # timezone
            0,            # sigfigs
            65535,        # snaplen
            1             # network (Ethernet)
        )
        self.file.write(header)
    
    def write(self, packet: PcapPacket):
        pkt_header = struct.pack('<IIII',
            packet.ts_sec,
            packet.ts_usec,
            len(packet.data),
            len(packet.data)
        )
        self.file.write(pkt_header)
        self.file.write(packet.data)
    
    def close(self):
        self.file.close()
