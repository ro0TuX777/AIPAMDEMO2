"""PE (Portable Executable) analysis mixin."""

import struct
import subprocess

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


class PEMixin:
    """PE-format specific analysis methods."""

    def _analyze_pe(self, file_path, content):
        """Analyze Windows PE file"""
        if not PEFILE_AVAILABLE:
            return None

        try:
            pe = pefile.PE(data=content)
        except Exception as e:
            return {'pe_error': str(e)}

        result = {
            'pe_info': {
                'machine': hex(pe.FILE_HEADER.Machine),
                'subsystem': pe.OPTIONAL_HEADER.Subsystem if hasattr(pe.OPTIONAL_HEADER, 'Subsystem') else 'Unknown',
                'entry_point': hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(pe.OPTIONAL_HEADER.ImageBase),
                'is_dll': pe.is_dll(),
                'is_exe': pe.is_exe(),
            },
            'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            'sections': [],
            'imports': [],
            'exports': [],
            'suspicious_imports': []
        }

        # Analyze sections
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            section_entropy = section.get_entropy()

            section_info = {
                'name': section_name,
                'virtual_address': hex(section.VirtualAddress),
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'entropy': round(section_entropy, 4),
                'characteristics': hex(section.Characteristics),
                'executable': bool(section.Characteristics & 0x20000000),
                'writable': bool(section.Characteristics & 0x80000000),
            }

            # Flag suspicious sections
            if section_entropy > 7.0:
                section_info['suspicious'] = 'High entropy - possibly packed/encrypted'
            if section_info['executable'] and section_info['writable']:
                section_info['suspicious'] = 'Executable and writable - suspicious'

            result['sections'].append(section_info)

        # Analyze imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                imports = []
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        imports.append(func_name)

                        # Check for suspicious imports
                        for severity, funcs in self.SUSPICIOUS_WIN_APIS.items():
                            if func_name in funcs:
                                result['suspicious_imports'].append({
                                    'function': func_name,
                                    'dll': dll_name,
                                    'severity': severity.upper()
                                })

                result['imports'].append({
                    'dll': dll_name,
                    'functions': imports[:50]  # Limit
                })

        # Analyze exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    result['exports'].append({
                        'name': exp.name.decode('utf-8', errors='ignore'),
                        'ordinal': exp.ordinal,
                        'address': hex(exp.address)
                    })

        pe.close()
        return result


    def _calculate_imphash(self, file_path):
        """Calculate import hash (imphash) for PE files"""
        if not PEFILE_AVAILABLE:
            return {'available': False, 'reason': 'pefile not installed'}
        try:
            pe = pefile.PE(str(file_path))
            imphash = pe.get_imphash()
            pe.close()
            return {'available': True, 'imphash': imphash if imphash else 'no imports'}
        except Exception as e:
            return {'available': False, 'reason': str(e)}

    def _analyze_rich_header(self, content):
        """Analyze PE Rich header for build environment fingerprinting"""
        # Rich header starts with "DanS" XORed with a key, ends with "Rich"
        rich_offset = content.find(b'Rich')
        if rich_offset == -1:
            return {'found': False}
        try:
            # The key is the 4 bytes after "Rich"
            key = struct.unpack('<I', content[rich_offset + 4:rich_offset + 8])[0]
            # Find "DanS" by XORing backwards
            dans_marker = struct.pack('<I', 0x536E6144 ^ key)
            dans_offset = content.rfind(dans_marker, 0, rich_offset)
            if dans_offset == -1:
                return {'found': True, 'parsed': False, 'reason': 'DanS marker not found'}
            # Parse entries (each 8 bytes, XORed with key)
            entries = []
            pos = dans_offset + 16  # Skip DanS + 3 padding DWORDs
            while pos < rich_offset:
                comp_id = struct.unpack('<I', content[pos:pos+4])[0] ^ key
                count = struct.unpack('<I', content[pos+4:pos+8])[0] ^ key
                product_id = (comp_id >> 16) & 0xFFFF
                build_id = comp_id & 0xFFFF
                entries.append({'product_id': product_id, 'build_id': build_id, 'count': count})
                pos += 8
            # Rich header hash for attribution
            import hashlib
            rich_hash = hashlib.md5(content[dans_offset:rich_offset + 8]).hexdigest()
            return {'found': True, 'parsed': True, 'entries': entries[:20],
                    'rich_hash': rich_hash, 'attribution_risk': 'HIGH',
                    'explanation': 'Rich header reveals compiler version, build tools, and development environment'}
        except Exception as e:
            return {'found': True, 'parsed': False, 'reason': str(e)}

    def _detect_section_anomalies(self, sections):
        """Detect anomalous section names and properties"""
        known_pe_sections = {'.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.edata', '.idata', '.tls', '.debug'}
        known_elf_sections = {'.text', '.data', '.bss', '.rodata', '.symtab', '.strtab', '.init', '.fini', '.plt', '.got'}
        anomalies = []
        for section in sections:
            name = section.get('name', '').strip('\x00').strip()
            if not name:
                continue
            # Check for unusual section names
            if name not in known_pe_sections and name not in known_elf_sections:
                if not name.startswith('.'):
                    anomalies.append({'section': name, 'issue': 'Non-standard section name (packer indicator)',
                                     'risk': 'HIGH'})
                else:
                    anomalies.append({'section': name, 'issue': 'Uncommon section name',
                                     'risk': 'MEDIUM'})
            # Check for executable + writable sections
            characteristics = section.get('characteristics', 0)
            if isinstance(characteristics, int):
                is_exec = characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
                is_write = characteristics & 0x80000000  # IMAGE_SCN_MEM_WRITE
                if is_exec and is_write:
                    anomalies.append({'section': name, 'issue': 'Section is both executable and writable (RWX)',
                                     'risk': 'CRITICAL'})
            # Check for zero-size sections
            size = section.get('size', section.get('virtual_size', 0))
            if size == 0:
                anomalies.append({'section': name, 'issue': 'Zero-size section (potential packing)',
                                 'risk': 'MEDIUM'})
            # Check for high entropy sections
            entropy = section.get('entropy', 0)
            if entropy > 7.5:
                anomalies.append({'section': name, 'issue': f'Very high entropy ({entropy:.2f}) — likely packed/encrypted',
                                 'risk': 'HIGH'})
        return anomalies

    def _detect_overlay(self, file_path, content):
        """Detect data appended after the PE/ELF structure (overlay)"""
        if not PEFILE_AVAILABLE:
            return {'checked': False}
        try:
            pe = pefile.PE(str(file_path))
            overlay_offset = pe.get_overlay_data_start_offset()
            pe.close()
            if overlay_offset and overlay_offset < len(content):
                overlay_size = len(content) - overlay_offset
                overlay_entropy = self._calculate_entropy(content[overlay_offset:])
                return {'found': True, 'offset': overlay_offset, 'size': overlay_size,
                        'entropy': overlay_entropy.get('value', 0) if isinstance(overlay_entropy, dict) else overlay_entropy,
                        'risk': 'HIGH' if overlay_size > 1024 else 'MEDIUM',
                        'explanation': 'Overlay data may contain hidden payloads, configs, or encrypted data'}
            return {'found': False}
        except Exception:
            return {'checked': False}

    def _validate_certificate(self, file_path):
        """Check for Authenticode signature / certificate validation"""
        if not PEFILE_AVAILABLE:
            return {'checked': False}
        try:
            pe = pefile.PE(str(file_path))
            has_cert = hasattr(pe, 'DIRECTORY_ENTRY_SECURITY')
            pe.close()
            if has_cert:
                return {'signed': True, 'risk': 'LOW',
                        'note': 'Binary is signed — verify certificate is not stolen/self-signed'}
            return {'signed': False, 'risk': 'MEDIUM',
                    'note': 'Binary is unsigned — may trigger AV/EDR alerts'}
        except Exception:
            return {'checked': False}

