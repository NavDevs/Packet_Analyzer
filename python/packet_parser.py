import struct


class PacketParser:
    @staticmethod
    def parse_ip_header(data: bytes, offset: int):
        if len(data) < offset + 20:
            return None
        
        version = (data[offset] >> 4) & 0xF
        if version != 4:
            return None
        
        ihl = data[offset] & 0xF
        header_len = ihl * 4
        
        if len(data) < offset + header_len:
            return None
        
        total_len = struct.unpack('!H', data[offset+2:offset+4])[0]
        ttl = data[offset + 8]
        protocol = data[offset + 9]
        
        src_ip = f"{data[offset+12]}.{data[offset+13]}.{data[offset+14]}.{data[offset+15]}"
        dst_ip = f"{data[offset+16]}.{data[offset+17]}.{data[offset+18]}.{data[offset+19]}"
        
        return {
            'version': version,
            'header_len': header_len,
            'total_len': total_len,
            'ttl': ttl,
            'protocol': protocol,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'next_offset': offset + header_len
        }
    
    @staticmethod
    def parse_tcp_header(data: bytes, offset: int):
        if len(data) < offset + 20:
            return None
        
        src_port = struct.unpack('!H', data[offset:offset+2])[0]
        dst_port = struct.unpack('!H', data[offset+2:offset+4])[0]
        seq_num = struct.unpack('!I', data[offset+4:offset+8])[0]
        ack_num = struct.unpack('!I', data[offset+8:offset+12])[0]
        
        data_offset = (data[offset+12] >> 4) & 0xF
        header_len = data_offset * 4
        
        flags = data[offset+13]
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'seq_num': seq_num,
            'ack_num': ack_num,
            'flags': flags,
            'header_len': header_len,
            'next_offset': offset + header_len
        }
    
    @staticmethod
    def parse_udp_header(data: bytes, offset: int):
        if len(data) < offset + 8:
            return None
        
        src_port = struct.unpack('!H', data[offset:offset+2])[0]
        dst_port = struct.unpack('!H', data[offset+2:offset+4])[0]
        length = struct.unpack('!H', data[offset+4:offset+6])[0]
        
        return {
            'src_port': src_port,
            'dst_port': dst_port,
            'length': length,
            'next_offset': offset + 8
        }
    
    @staticmethod
    def parse_ethernet_header(data: bytes, offset: int):
        if len(data) < offset + 14:
            return None
        
        ether_type = struct.unpack('!H', data[offset+12:offset+14])[0]
        
        return {
            'ether_type': ether_type,
            'next_offset': offset + 14
        }
    
    @staticmethod
    def parse_packet(data: bytes):
        result = {
            'valid': False,
            'src_ip': None,
            'dst_ip': None,
            'protocol': None,
            'src_port': 0,
            'dst_port': 0,
            'payload': b'',
            'tcp_flags': 0
        }
        
        eth = PacketParser.parse_ethernet_header(data, 0)
        if not eth:
            return result
        
        if eth['ether_type'] != 0x0800:
            return result
        
        ip = PacketParser.parse_ip_header(data, eth['next_offset'])
        if not ip:
            return result
        
        result['src_ip'] = ip['src_ip']
        result['dst_ip'] = ip['dst_ip']
        result['protocol'] = ip['protocol']
        
        if ip['protocol'] == 6:
            tcp = PacketParser.parse_tcp_header(data, ip['next_offset'])
            if tcp:
                result['src_port'] = tcp['src_port']
                result['dst_port'] = tcp['dst_port']
                result['tcp_flags'] = tcp['flags']
                result['payload'] = data[tcp['next_offset']:]
        
        elif ip['protocol'] == 17:
            udp = PacketParser.parse_udp_header(data, ip['next_offset'])
            if udp:
                result['src_port'] = udp['src_port']
                result['dst_port'] = udp['dst_port']
                result['payload'] = data[udp['next_offset']:]
        
        result['valid'] = True
        return result
