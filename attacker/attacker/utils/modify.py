import lief
import random
import tempfile
import os
import subprocess


class PEFileModifier(object):
    def __init__(self, file_content: bytes):
        self.bytez = file_content
        self.packed_section_names = {'.aspack', '.adata', 'ASPack', '.ASPack', '.boom', '.ccg', '.charmve', 'BitArts', 'DAStub',
                                     '!EPack', '.ecode', '.edata', '.enigma1', '.enigma2', '.enigma2', '.FSG!', '.gentee', 'kkrunchy',
                                     'lz32.dll', '.mackt', '.MaskPE', 'MEW', '.mnbvcx1', '.mnbvcx2', '.MPRESS1', '.MPRESS2', '.neolite',
                                     '.neolit', '.nsp1', '.nsp0', '.nsp2', 'nps1', 'nps0', 'nps2', '.packed', 'pebundle', 'PEBundle',
                                     'PEC2TO', 'PECompact2', 'PE2', 'pec', 'pec1', 'pec2', 'pec2', 'pec3', 'pec4', 'pec5', 'pec6',
                                     'PEC2MO', 'PELOCKnt', '.perplex', 'PESHiELD', '.petite', '.pinclie', 'ProCrypt', '.RLPack',
                                     '.rmnet', 'RCryptor', '.RPCrypt', '.seau', ',sforce3', '.shrink1', '.shrink2', '.shrink3',
                                     '.spack', '.svkp', 'Themida', '.Themida', '.taz', '.tsuarch', '.tsustub', '.packed', 'PEPACK!!',
                                     '.Upack', '.ByDwing', 'UPX0', 'UPX1', 'UPX2', 'UPX3', 'UPX!', '.UPX0', '.UPX1', '.UPX2',
                                     '.vmp0', '.vmp1', '.vmp2', 'VProtect', '.winapi', 'WinLicen', '_winzip_', '.WWPACK', 'WWP32', '.yP', '.y0da'}

    def _build(self, pe, imports=False):
        builder = lief.PE.Builder(pe)
        if imports:
            # patch the original import table in order to redirect functions to the new import table
            builder.build_imports(True).patch_imports(True)  
        builder.build()
        return builder.get_build()

    def _ispacked(self, pe):
        for s in pe.sections:
            if s.name in self.packed_section_names:
                return True
        return False

    def _section_rename_if_exists(self, pe, section_name, target_name):
        for s in pe.sections:
            if s.name == section_name:
                break
        if s.name == section_name:
            s.name = target_name

    def add_section(self, section_name: str, characteristics: int, section_content: bytes):
        pe = lief.parse(raw=self.bytez)
        if self._ispacked(pe):
            return  # don't mess with sections if the file is packed
        replace_name = '.' + ''.join(list(map(chr, [random.randint(ord('a'), ord('z')) for _ in range(6)])))  # example: .nzomcu
        self._section_rename_if_exists(pe, section_name, replace_name)  # rename if exists
        section = lief.PE.Section(name=section_name, content=list(section_content), characteristics=characteristics)
        pe.add_section(section, lief.PE.SECTION_TYPES.UNKNOWN)
        self.bytez = self._build(pe)

    def rename_section_(self, section_name: str, target_name: str):
        pe = lief.parse(raw=self.bytez)
        if self._ispacked(pe):
            return  # don't mess with sections if the file is packed
        self._section_rename_if_exists(pe, section_name, target_name)  # rename if exists
        self.bytez = self._build(pe)  # idempotent if the section doesn't exist

    def set_timestamp(self, timestamp: int):
        pe = lief.parse(raw=self.bytez)
        pe.header.time_date_stamps = timestamp
        self.bytez = self._build(pe)

    def append_overlay(self, content: bytes):
        self.bytez += content

    def add_imports(self, library, functions):
        pe = lief.parse(raw=self.bytez)
        lib = pe.add_library(library)
        for f in functions:
            lib.add_entry(f)
        self.bytez = self._build(pe)

    def upx_unpack(self):
        # dump to a temporary file
        tmpfilename = os.path.join(
            tempfile._get_default_tempdir(), next(tempfile._get_candidate_names()))

        with open(tmpfilename, 'wb') as outfile:
            outfile.write(self.bytez)

        # test with upx -t
        with open(os.devnull, 'w') as DEVNULL:
            retcode = subprocess.call(
                ['upx', tmpfilename, '-t'], stdout=DEVNULL, stderr=DEVNULL
            )

        if retcode == 0:
            with open(os.devnull, 'w') as DEVNULL:
                retcode = subprocess.call(
                    ['upx', tmpfilename, '-d', '-o', tmpfilename + '_unpacked'], stdout=DEVNULL, stderr=DEVNULL
                )
            if retcode == 0:
                with open(tmpfilename + '_unpacked', 'rb') as result:
                    self.bytez = result.read()

        os.unlink(tmpfilename)

        return

    @property
    def content(self):
        return bytes(self.bytez)


if __name__ == '__main__':
    import glob
    import lief
    from collections import defaultdict
    sections = []
    overlays = []
    imports = defaultdict(set)
    timestamps = []

    for fn in glob.glob('/data/samples/validation/benign/*'):
        pe = lief.parse(fn)
        for s in pe.sections:
            sections.append((s.name, s.characteristics, bytes(s.content)))
        for i in pe.imports:
            for f in i.entries:
                imports[i.name].add(f.name)
        timestamps.append(pe.header.time_date_stamps)
        overlays.append(bytes(pe.overlay))

    imports = [(k, list(v)) for k, v in imports.items()]

    # let's sort by content length
    sections.sort(key=lambda x: len(x[2]), reverse=True)
    overlays.sort(key=lambda x: len(x), reverse=True)
    imports.sort(key=lambda x: len(x[1]), reverse=True)
    timestamps = [min(timestamps), max(timestamps)]

    # let's filter sections
    from collections import Counter

    def updatecounter(k, counter):
        counter.update([k])
        return counter[k]

    scounter = Counter()
    sections = [s for s in sections if updatecounter(f'{s[0]}{s[1]}', scounter) <= 2]  # how many of each name/characteristics?

    overlays = [o for o in overlays if len(o) >= 1024]

    imports = [i for i in imports if len(i[1]) >= 5]

    # open a file and modify it
    malicious_fn = '/data/samples/validation/malicious/002'
    bytez = open(malicious_fn, 'rb').read()

    modpe = PEFileModifier(bytez)
    modpe.add_section(*sections[0])
    modpe.append_overlay(overlays[0])
    modpe.set_timestamp(timestamps[0])
    modpe.add_imports(*imports[0])
    bytez2 = modpe.content
    print(len(bytez), len(bytez2))
