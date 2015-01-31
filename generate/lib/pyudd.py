# -*- coding: Latin-1 -*-
#!/usr/bin/env python

"""PyUdd, a python module for OllyDbg .UDD files

Ange Albertini 2010, Public domain
"""

__author__ = 'Ange Albertini'
__contact__ = 'ange@corkami.com'
__revision__ = "$Revision$"
__version__ = '0.1 r%d' 

import struct

HDR_STRING = "Mod\x00"
FTR_STRING = "\nEnd"

#TODO: find standard notation to keep it inside init_mappings
udd_formats = [
    (11, "Module info file v1.1\x00"),
    (20, "Module info file v2.0\x00"),
		(20, "Module info file v2.01g\x00"),
    ]

def init_mappings():
    """initialize constants' mappings"""
    format_ids = [
        "STRING",
        "DDSTRING",
        "MRUSTRING",
        "EMPTY",
        "VERSION",
        "DWORD",
        "DD2",
        "DD2STRING",
        "BIN",
        "NAME",
        "CRC2",
        ]

    F_ = dict([(e, i) for i, e in enumerate(format_ids)])

    udd_formats = [
        (11, "Module info file v1.1\x00"),
        (20, "Module info file v2.0\x00"),
				(20, "Module info file v2.01g\x00"),
        ]

    Udd_Formats = dict(
        [(e[1], e[0]) for e in udd_formats] +
        udd_formats)

    #OllyDbg 1.1
    chunk_types11 = [
        ("Header", HDR_STRING, F_["STRING"]),
        ("Footer", FTR_STRING, F_["EMPTY"]),
        ("Filename", "\nFil", F_["STRING"]),
        ("Version", "\nVer", F_["VERSION"]),
        ("Size", "\nSiz", F_["DWORD"]),
        ("Timestamp", "\nTst", F_["DD2"]),
        ("CRC", "\nCcr", F_["DWORD"]),
        ("Patch", "\nPat", F_["BIN"]),
        ("Bpc", "\nBpc", F_["BIN"]),
        ("Bpt", "\nBpt", F_["BIN"]),
        ("HwBP", "\nHbr", F_["BIN"]),
        ("Save", "\nSva", F_["BIN"]), # sometimes 4, sometimes 5 ?
        ("AnalyseHint", "\nAht", F_["BIN"]),

        ("CMD_PLUGINS", "\nUs0", F_["DDSTRING"]), # multiline, needs escaping
        ("U_LABEL", "\nUs1", F_["DDSTRING"]),
        ("A_LABEL", "\nUs4", F_["DDSTRING"]),
        ("U_COMMENT", "\nUs6", F_["DDSTRING"]),
        ("BPCOND", "\nUs8", F_["DDSTRING"]),
        ("ApiArg", "\nUs9", F_["DDSTRING"]),
        ("USERLABEL", "\nUs1", F_["DDSTRING"]),
        ("Watch", "\nUsA", F_["DDSTRING"]),

        ("US2", "\nUs2", F_["BIN"]),
        ("US3", "\nUs3", F_["BIN"]),
        ("_CONST", "\nUs5", F_["BIN"]),
        ("A_COMMENT", "\nUs7", F_["BIN"]),
        ("FIND?", "\nUsC", F_["BIN"]),
        ("SOURCE?", "\nUsI", F_["BIN"]),


        ("MRU_Inspect","\nUs@", F_["MRUSTRING"]),
        ("MRU_Asm", "\nUsB", F_["MRUSTRING"]),
        ("MRU_Goto", "\nUsK", F_["MRUSTRING"]), #?
        ("MRU_Explanation", "\nUs|", F_["MRUSTRING"]), # logging bp explanation
        ("MRU_Expression", "\nUs{", F_["MRUSTRING"]), # logging bp expression
        ("MRU_Watch", "\nUsH", F_["MRUSTRING"]),
        ("MRU_Label", "\nUsq", F_["MRUSTRING"]), #?
        ("MRU_Comment", "\nUsv", F_["MRUSTRING"]), #?
        ("MRU_Condition", "\nUsx", F_["MRUSTRING"]), #?

        ("MRU_CMDLine", "\nCml", F_["STRING"]), #?


        ("LogExpression", "\nUs;", F_["DDSTRING"]), # logging bp expression
        ("ANALY_COMM", "\nUs:", F_["DDSTRING"]), #
        ("US?", "\nUs?", F_["DDSTRING"]), #?
        ("TracCond", "\nUsM", F_["DDSTRING"]), # tracing condition
        ("LogExplanation", "\nUs<", F_["DDSTRING"]), # logging bp explanation
        ("AssumedArgs", "\nUs=", F_["DDSTRING"]), # Assumed arguments
        ("CFA", "\nCfa", F_["DD2"]), #?
        ("CFM", "\nCfm", F_["DD2STRING"]), #?
        ("CFI", "\nCfi", F_["DD2"]), #?

        ("US>", "\nUs>", F_["BIN"]), #?
        ("ANC", "\nAnc", F_["BIN"]), #?
        ("JDT", "\nJdt", F_["BIN"]), #?
        ("PRC", "\nPrc", F_["BIN"]), #?
        ("SWI", "\nSwi", F_["BIN"]), #?
        ]

    #OllyDbg 2
    chunk_types20 = [
        ("Header", HDR_STRING, F_["STRING"]),
        ("Footer", FTR_STRING, F_["EMPTY"]),
        ("Filename", "\nFil", F_["STRING"]),

        ("Infos", "\nFcr", F_["CRC2"]), #?
        ("Name", "\nNam", F_["NAME"]), #?
        ("Data", "\nDat", F_["NAME"]), #?
        ("MemMap", "\nMba", F_["DDSTRING"]), #?

        ("LSA", "\nLsa", F_["NAME"]), # MRU entries

        ("JDT", "\nJdt", F_["BIN"]), #?
        ("PRC", "\nPrc", F_["BIN"]), #?
        ("SWI", "\nSwi", F_["BIN"]), #?

        ("CBR", "\nCbr", F_["BIN"]), #?
        ("LBR", "\nLbr", F_["BIN"]), #?
        ("ANA", "\nAna", F_["BIN"]), #?
        ("CAS", "\nCas", F_["BIN"]), #?
        ("PRD", "\nPrd", F_["BIN"]), #?
        ("Save", "\nSav", F_["BIN"]), #?
        ("RTC", "\nRtc", F_["BIN"]), #?
        ("RTP", "\nRtp", F_["BIN"]), #?
        ("Int3", "\nIn3", F_["BIN"]), #?
        ("MemBP", "\nBpm", F_["BIN"]), #?
        ("HWBP", "\nBph", F_["BIN"]), #?
        ]

    Chunk_Types11 = dict(
        [(e[1], e[0]) for e in chunk_types11] +
        [(e[0], e[1]) for e in chunk_types11]
        )

    Chunk_Types20 = dict(
        [(e[1], e[0]) for e in chunk_types20] +
        [(e[0], e[1]) for e in chunk_types20]
        )

    Chunk_Types = {
        11: Chunk_Types11,
        20: Chunk_Types20
        }

    # no overlapping of formats yet so they're still merged
    #
    Chunk_Formats = dict(
        [(e[2], e[0]) for e in chunk_types11] +
        [(e[0], e[2]) for e in chunk_types11] +

        [(e[2], e[0]) for e in chunk_types20] +
        [(e[0], e[2]) for e in chunk_types20]
        )

    olly2cats = [
        # used in DATA and NAME
        #
        ('!', "UserLabel"),
        ('0', "UserComment"),
        ('1', "Import"),
        ('2', "APIArg"),
        ('3', "APICall"),
        ('4', "Member"),
        ('6', "Unk6"),
        ('*', "Struct"),

        # only used in LSA ?
        #
        ('`', 'mru_label'),
        ('a', 'mru_asm'),
        ('c', 'mru_comment'),
        ('d', 'watch'),
        ('e', 'mru_goto'),

        ('p', 'trace_condition1'),
        ('q', 'trace_condition2'),
        ('r', 'trace_condition3'),
        ('s', 'trace_condition4'),
        ('t', 'trace_command1'),
        ('u', 'trace_command2'),

        ('v', 'protocol_start'),
        ('w', 'protocol_end'),

        ('Q', 'log_explanation'),
        ('R', 'log_condition'),
        ('S', 'log_expression'),

        ('U', 'mem_explanation'),
        ('V', 'mem_condition'),
        ('W', 'mem_expression'),

        ('Y', 'hbplog_explanation'),
        ('Z', 'hbplog_condition'),
        ('[', 'hbplog_expression'),

        ]

    Olly2Cats = dict(
        [(e[1], e[0]) for e in olly2cats] +
        olly2cats)

    return Udd_Formats, F_, Chunk_Types, Chunk_Formats, Olly2Cats

UDD_FORMATS, F_, CHUNK_TYPES, CHUNK_FORMATS, OLLY2CATS = init_mappings()

def binstr(data):
    """return a stream as hex sequence"""
    return " ".join(["%02X" % ord(c) for c in data])

def elbinstr(data):
    """return a stream as hex sequence, ellipsed if too long"""
    if len(data) < 10:
        return binstr(data)
    return "(%i) %s ... %s" % (len(data), binstr(data[:10]), binstr(data[-10:]))

class Error(Exception):
    """custom error class"""
    pass

def crc32mpeg(buffer_):
    """computes the CRC32 MPEG of a buffer"""
    crc = 0xffffffff
    for c in buffer_:
        octet = ord(c)

        for i in range(8):
            topbit = crc & 0x80000000
            if octet & (0x80 >> i):
                topbit ^= 0x80000000
            crc <<= 1
            if topbit:
                crc ^= 0x4c11db7
        crc &= 0xffffffff

    return crc

def getcrc(filename):
    """returns the UDD crc of a file, by its filename"""
    # probably not always correct
    import pefile
    pe = pefile.PE(filename)
    sec = pe.sections[0]
    align = pe.OPTIONAL_HEADER.SectionAlignment

    data = sec.get_data(sec.VirtualAddress)

    ActualSize = max(sec.Misc_VirtualSize, sec.SizeOfRawData)
    data += "\0" * (ActualSize - len(data))

    rem = ActualSize % align
    if rem:
        data += "\0" * (align - rem)

    return crc32mpeg(data)

def getTimestamp(filename):
    """read LastModified timestamp and return as a binary buffer"""
    import ctypes
    mtime = ctypes.c_ulonglong(0)

    h = ctypes.windll.kernel32.CreateFileA(
        ctypes.c_char_p(filename),
        0, 3, 0, 3, 0x80, 0)
    ctypes.windll.kernel32.GetFileTime(h, 0,0, ctypes.pointer(mtime))
    ctypes.windll.kernel32.CloseHandle(h)
    return struct.pack("<Q", mtime.value)

def getFileInfo(filename):
    """return file's timestamp, crc and size"""
    import os
    import stat
    time_ = getTimestamp(filename)
    crc = getcrc(filename)
    size = os.stat(filename)[stat.ST_SIZE]
    return time_, crc, size


def read_next_chunk(f):
    """read next Udd chunk"""
    ct = f.read(4)
    size = struct.unpack("<I", f.read(4))[0]
    cd = f.read(size)

    return ct, cd


def write_chunk(f, ct, cd):
    """write a chunk"""
    f.write(ct)
    f.write(struct.pack("<I", len(cd)))
    f.write(cd)
    return


def make_chunk(ct, cd):
    """put together chunk types and data with a few checks"""
    if len(ct) != 4:
        raise Error("invalid chunk name length")
    if len(cd) > 255:
        raise Error("invalid chunk data length")

    return [ct, cd]


def build_data(format_, info):
    """generate a chunk data depending on the format"""
    if format_ == F_["DWORD"]:
        return "%s" % (struct.pack("<I", info["dword"]))
    if format_ in [F_["DDSTRING"], F_["MRUSTRING"]]:
        return "%s%s\x00" % (struct.pack("<I", info["dword"]), info["text"])
    else:
        raise Error("format not supported for building")


#TODO: merge those into a real make_chunk or something - support format 2
#
def make_comment_chunk(info, format_):
    """generate a user comment chunk depending on the format"""
    if format_ == 11:
        return make_chunk(
            CHUNK_TYPES[format_]["U_COMMENT"],
            build_data(CHUNK_FORMATS["U_LABEL"], info)
            )
    else:
        raise Error("Not supported")

def make_label_chunk(info, format_):
    """generate a user label chunk depending on the format"""
    if format_ == 11:
        return make_chunk(
            CHUNK_TYPES[format_]["U_LABEL"],
            build_data(CHUNK_FORMATS["U_LABEL"], info)
            )

    else:
        raise Error("Not supported")


def expand_chunk(chunk, format_):
    """Extract information from the chunk data"""

    ct, cd = chunk
    if ct not in CHUNK_TYPES[format_]:
        return cd

    cf = CHUNK_FORMATS[CHUNK_TYPES[format_][ct]]
    if cf == F_["STRING"]:
        result = {"string": cd}

    elif cf in [F_["DDSTRING"], F_["MRUSTRING"]]:
        result = {
            "dword": struct.unpack("<I", cd[:4])[0],
            "text": cd[4:].rstrip("\x00").encode('string-escape')
            }

    elif cf == F_["NAME"]:
        #name can be null, no 00 in that case
        #if lptype is not present then no type
        RVA = cd[:4]
        buffer_ = cd[4:]
        RVA = struct.unpack("<I", RVA)[0]
        buffer_ = buffer_.rstrip("\x00")

        result = {"RVA": RVA, "category": buffer_[0]}

        buffer_ = buffer_[1:]

        for i, c in enumerate(buffer_):
            if ord(c) >= 0x80:
                found = i
                break
        else:
            name = buffer_
            if buffer_:
                result["name"] = buffer_
            return result

        name = buffer_[:found]
        lptype = buffer_[found]
        type_ = buffer_[found + 1:]

        # should be in rendering ?
        #
        name = name.rstrip("\x00")
        if name:
            result["name"] = name

        # should be in rendering ?
        #
        result["lptype"] = "*" if lptype == "\xa0" else "%i" % ord(lptype)

        result["type_"] = type_

    elif cf == F_["DD2STRING"]:
        result = list(struct.unpack("<2I", cd[:8])) + [cd[8:].rstrip("\x00")]
    elif cf == F_["EMPTY"]:
        result = None
    elif cf == F_["CRC2"]:
        dwords = struct.unpack("<6I", cd)
        result = {
            "size":dwords[0],
            "timestamp": " ".join("%08X" % e for e in (dwords[1:3])),
            "unk": dwords[3],
						"unk2": dwords[4],
						"unk3": dwords[5],
						
            }
    elif cf == F_["VERSION"]:
        result = {"version":struct.unpack("<4I", cd)}
    elif cf == F_["DWORD"]:
        result = {"dword": struct.unpack("<I", cd)}
    elif cf == F_["DD2"]:
        result = {"dwords": struct.unpack("<2I", cd)}
    elif cf == F_["BIN"]:
        result = {"binary": cd}
    else:
        result = cd
    return result


def print_chunk(chunk, format_):
    """Pretty print chunk data after expansion"""

    ct, cd = chunk
    info = expand_chunk(chunk, format_)
    if ct not in CHUNK_TYPES[format_]:
        return elbinstr(info)

    cf = CHUNK_FORMATS[CHUNK_TYPES[format_][ct]]

    if cf == F_["STRING"]:
        result = info["string"].rstrip("\x00")

    elif cf == F_["DDSTRING"]:
        result = "%(dword)08X %(text)s" % (info)

    elif cf == F_["MRUSTRING"]:
        result = "%(dword)i %(text)s" % (info)

    elif cf == F_["NAME"]:
        if info["category"] in OLLY2CATS:
            info["category"] = OLLY2CATS[info["category"]]
        result = ["%(RVA)08X (%(category)s)" % info]

        if "name" in info:
            result += ["%(name)s" % info]
        if "type_" in info:
            result += ["type:%(lptype)s %(type_)s" % info]

        result = " ".join(result)

    elif cf == F_["DD2STRING"]:
        result = "%08X %08X %s" % tuple(info)

    elif cf == F_["EMPTY"]:
        result = ""

    elif cf == F_["CRC2"]:
        result = "Size: %(size)i Time:%(timestamp)s unk:%(unk)08X" % info

    elif cf == F_["VERSION"]:
        result = "%i.%i.%i.%i" % info["version"]

    elif cf == F_["DWORD"]:
        result = "%08X" % info["dword"]

    elif cf == F_["DD2"]:
        result = "%08X %08X" % info["dwords"]

    elif cf == F_["BIN"]:
        result = elbinstr(info["binary"])
    else:
        result = cd
    return result


class Udd(object):
    """OllyDbg UDD file format class"""

    def __init__(self, filename=None, format_=None):
        """initialization. load file if given"""
        self.__data = {}
        self.__chunks = []
        self.__warnings = []

        self.__format = 11 if format_ is None else format_

        if filename is not None:
            self.load(filename)
        return


    def load(self, filename):
        """load UDD file from filename"""
        try:
            f = open(filename, "rb")
            ct, cd =  read_next_chunk(f)

            if not (ct == HDR_STRING and
                cd in (e[1] for e in udd_formats)):
                raise Error("Invalid HEADER chunk")

            self.__format = UDD_FORMATS[cd]

            self.__chunks.append([ct, cd])
            while (True):
                ct, cd = read_next_chunk(f)

                if ct not in CHUNK_TYPES[self.__format]:
                    self.__warnings.append(
                        "Warning (offset %08X) unknown chunk type: '%s' %s" %
                            (f.tell(), ct.lstrip("\n"), elbinstr(cd))
                        )
                self.__chunks.append([ct, cd])
                if (ct, cd) == (CHUNK_TYPES[self.__format]["Footer"] , ""):
                    break

        finally:
            f.close()
        return


    def save(self, filename):
        """(over)writes UDD file to disk"""
        f = open(filename, "wb")
        for ct, cd in self.__chunks:
            write_chunk(f, ct, cd)
        f.close()
        return


    def set_chunk(self, pos, chunk):
        """give new values to a chunk"""
        self.__chunks[pos] = chunk
        return


    def get_chunk(self, pos):
        """return chunk contents"""
        return self.__chunks[pos]


    def add_chunk(self, chunk):
        """append a chunk before the footer"""
        if not self.find_chunk(chunk):
            self.__chunks.insert(-1, chunk)
        return


    def append_chunk(self, chunk):
        """blindly append the chunk"""
        self.__chunks.append(chunk)
        return

    def get_format(self):
        """return UDD file format"""
        return self.__format


    def find_by_type(self, type_):
        """return chunk indexes matching the given type"""
        found = []

        for i, c in enumerate(self.__chunks):
            if c[0] == type_:
                found += [i]
        return found


    def find_by_types(self, types):
        """return chunk indexes matching any of the given types"""
        found = []

        for i, c in enumerate(self.__chunks):
            if c[0] in types:
                found += [i]
        return found


    def find_chunk(self, chunk):
        """lookup chunk by its type and data"""
        found = []

        for i, c in enumerate(self.__chunks):
            if c == chunk:
                found += [i]
        return found if found else None


    def __repr__(self):
        """pretty print of a UDD"""
        r = []
        for i in self.__chunks:
            if i[0] in CHUNK_TYPES[self.__format]:
                s = ["%s:" % CHUNK_TYPES[self.__format][i[0]]]
            else:
                s = ["UNK[%s]:" % i[0][1:4]]
            s += [print_chunk(i, self.__format)]
            r += ["".join(s)]
        return "\n".join(r)

