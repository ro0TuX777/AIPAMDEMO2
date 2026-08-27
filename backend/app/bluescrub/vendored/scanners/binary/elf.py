"""ELF analysis mixin."""

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    PYELFTOOLS_AVAILABLE = True
except ImportError:
    PYELFTOOLS_AVAILABLE = False


class ELFMixin:
    """ELF-format specific analysis methods."""

    def _analyze_elf(self, file_path):
        """Analyze Linux ELF file"""
        if not PYELFTOOLS_AVAILABLE:
            return None

        try:
            with open(file_path, 'rb') as f:
                elf = ELFFile(f)

                result = {
                    'elf_info': {
                        'class': elf.elfclass,
                        'endian': 'little' if elf.little_endian else 'big',
                        'machine': elf.header['e_machine'],
                        'type': elf.header['e_type'],
                        'entry_point': hex(elf.header['e_entry']),
                    },
                    'entry_point': elf.header['e_entry'],
                    'sections': [],
                    'symbols': [],
                    'suspicious_symbols': []
                }

                # Analyze sections
                for section in elf.iter_sections():
                    section_info = {
                        'name': section.name,
                        'type': section['sh_type'],
                        'address': hex(section['sh_addr']),
                        'size': section['sh_size'],
                        'flags': section['sh_flags'],
                        'executable': bool(section['sh_flags'] & 0x4),
                        'writable': bool(section['sh_flags'] & 0x1),
                    }
                    result['sections'].append(section_info)

                    # Extract symbols
                    if isinstance(section, SymbolTableSection):
                        for symbol in section.iter_symbols():
                            if symbol.name:
                                result['symbols'].append(symbol.name)

                                # Check suspicious
                                for severity, funcs in self.SUSPICIOUS_LINUX_FUNCS.items():
                                    if symbol.name in funcs:
                                        result['suspicious_symbols'].append({
                                            'function': symbol.name,
                                            'severity': severity.upper()
                                        })

                return result

        except Exception as e:
            return {'elf_error': str(e)}

