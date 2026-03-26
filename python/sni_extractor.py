from typing import Optional


def read_uint16_be(data: bytes, offset: int) -> int:
    return (data[offset] << 8) | data[offset + 1]


def read_uint24_be(data: bytes, offset: int) -> int:
    return (data[offset] << 16) | (data[offset + 1] << 8) | data[offset + 2]


class SNIExtractor:
    CONTENT_TYPE_HANDSHAKE = 0x16
    HANDSHAKE_CLIENT_HELLO = 0x01
    EXTENSION_SNI = 0x0000
    SNI_TYPE_HOSTNAME = 0x00
    
    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        
        if payload[0] != SNIExtractor.CONTENT_TYPE_HANDSHAKE:
            return False
        
        version = read_uint16_be(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        
        if payload[5] != SNIExtractor.HANDSHAKE_CLIENT_HELLO:
            return False
        
        return True
    
    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload):
            return None
        
        try:
            offset = 9
            
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            
            cipher_suites_len = read_uint16_be(payload, offset)
            offset += 2 + cipher_suites_len
            
            compression_len = payload[offset]
            offset += 1 + compression_len
            
            extensions_len = read_uint16_be(payload, offset)
            offset += 2
            
            ext_end = offset + extensions_len
            if ext_end > len(payload):
                ext_end = len(payload)
            
            while offset + 4 <= ext_end:
                ext_type = read_uint16_be(payload, offset)
                ext_len = read_uint16_be(payload, offset + 2)
                offset += 4
                
                if offset + ext_len > ext_end:
                    break
                
                if ext_type == SNIExtractor.EXTENSION_SNI:
                    if ext_len < 5:
                        break
                    
                    sni_list_len = read_uint16_be(payload, offset)
                    if sni_list_len < 3:
                        break
                    
                    sni_type = payload[offset + 2]
                    sni_len = read_uint16_be(payload, offset + 3)
                    
                    if sni_type != SNIExtractor.SNI_TYPE_HOSTNAME:
                        break
                    
                    if sni_len > ext_len - 5:
                        break
                    
                    sni = payload[offset + 5:offset + 5 + sni_len].decode('utf-8', errors='ignore')
                    return sni
                
                offset += ext_len
        except (IndexError, ValueError):
            pass
        
        return None


class HTTPHostExtractor:
    HTTP_METHODS = [b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE', b'PATC', b'OPTI']
    
    @staticmethod
    def is_http_request(payload: bytes) -> bool:
        if len(payload) < 4:
            return False
        
        for method in HTTPHostExtractor.HTTP_METHODS:
            if payload.startswith(method):
                return True
        
        return False
    
    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not HTTPHostExtractor.is_http_request(payload):
            return None
        
        try:
            text = payload.decode('utf-8', errors='ignore')
            
            for line in text.split('\n'):
                line_lower = line.lower()
                if line_lower.startswith('host:'):
                    host = line[5:].strip()
                    if ':' in host:
                        host = host[:host.index(':')]
                    return host.strip()
        except Exception:
            pass
        
        return None


class DNSExtractor:
    @staticmethod
    def is_dns_query(payload: bytes) -> bool:
        if len(payload) < 12:
            return False
        
        flags = payload[2]
        if flags & 0x80:
            return False
        
        qdcount = (payload[4] << 8) | payload[5]
        return qdcount > 0
    
    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        if not DNSExtractor.is_dns_query(payload):
            return None
        
        try:
            offset = 12
            domain = []
            
            while offset < len(payload):
                label_len = payload[offset]
                
                if label_len == 0:
                    break
                
                if label_len > 63:
                    break
                
                offset += 1
                if offset + label_len > len(payload):
                    break
                
                label = payload[offset:offset + label_len].decode('utf-8', errors='ignore')
                domain.append(label)
                offset += label_len
            
            if domain:
                return '.'.join(domain)
        except Exception:
            pass
        
        return None
