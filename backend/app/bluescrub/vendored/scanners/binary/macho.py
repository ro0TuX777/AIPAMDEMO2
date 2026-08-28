"""Mach-O analysis mixin."""

import struct


class MachOMixin:
    """Mach-O format specific analysis methods."""

    def _analyze_macho(self, file_path, content):
        """Analyze Mach-O binaries (macOS)"""
        result = {'format': 'Mach-O', 'load_commands': [], 'sections': []}
        try:
            # Parse Mach-O header
            if content[:4] in (b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe'):
                is_64 = content[:4] == b'\xcf\xfa\xed\xfe'
                header_fmt = '<IIIIIII' if is_64 else '<IIIIIIII'
                header_size = 32 if is_64 else 28
                if len(content) < header_size:
                    return result
                fields = struct.unpack_from(header_fmt[:7 if not is_64 else 7], content, 4)
                cpu_type, cpu_subtype, filetype, ncmds, sizeofcmds = fields[0], fields[1], fields[2], fields[3], fields[4]
                result['cpu_type'] = cpu_type
                result['filetype'] = filetype
                result['num_load_commands'] = ncmds
                result['is_64bit'] = is_64
                # Parse load commands for interesting info
                offset = 32 if is_64 else 28
                for _ in range(min(ncmds, 50)):
                    if offset + 8 > len(content):
                        break
                    cmd, cmdsize = struct.unpack_from('<II', content, offset)
                    cmd_names = {0x1: 'LC_SEGMENT', 0x19: 'LC_SEGMENT_64', 0xC: 'LC_LOAD_DYLIB',
                                0xE: 'LC_LOAD_WEAK_DYLIB', 0x24: 'LC_VERSION_MIN_MACOSX',
                                0x2A: 'LC_RPATH', 0x26: 'LC_CODE_SIGNATURE',
                                0x80000022: 'LC_DYLD_INFO_ONLY', 0xD: 'LC_ID_DYLIB'}
                    cmd_name = cmd_names.get(cmd, f'LC_0x{cmd:x}')
                    result['load_commands'].append({'cmd': cmd_name, 'size': cmdsize})
                    offset += cmdsize
            # If LIEF is available, use it for deeper analysis
            if LIEF_AVAILABLE:
                try:
                    binary = lief.parse(str(file_path))
                    if binary:
                        for section in binary.sections:
                            result['sections'].append({
                                'name': section.name,
                                'size': section.size,
                                'entropy': section.entropy,
                            })
                except Exception:
                    pass
            return result
        except Exception as e:
            result['error'] = str(e)
            return result

