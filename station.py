import timaccop 
from Crypto.Cipher import AES
from collections import namedtuple
import struct
import os

masterkey = bytearray(bytes.fromhex("D306D9348E29E5E358BF2934812002C1"))
filename = "/storage/Projects/eink-display/einkTags_0001/dmitrygr-eink/imgTools/conv.bmp"

SHORT_ADDRESS = [ 0x49, 0x35 ]
EXTENDED_ADDRESS = [ 0x35, 0x49, 0xD9, 0x14, 0x00, 0x4B, 0x12, 0x00 ] #reversed
PANID = [ 0x47, 0x44 ]

PKT_ASSOC_REQ			= (0xF0)
PKT_ASSOC_RESP			= (0xF1)
PKT_CHECKIN				= (0xF2)
PKT_CHECKOUT			= (0xF3)
PKT_CHUNK_REQ			= (0xF4)
PKT_CHUNK_RESP			= (0xF5)

def send_data(dst, data):
    dsn = 0 #TODO: increment
    hdr = bytearray.fromhex("41cc")
    hdr.append(dsn)
    hdr.extend(PANID)
    hdr.extend(reversed(dst))
    hdr.extend(EXTENDED_ADDRESS)
    #print("hdr:", hdr.hex())

    cntr = bytearray.fromhex("00000000")
    nonce = bytearray.fromhex("00000000")
    nonce.extend(EXTENDED_ADDRESS)
    nonce.append(0)
    #print("nonce:", nonce.hex())

    cipher = AES.new(masterkey, AES.MODE_CCM, nonce, mac_len=4)
    cipher.update(hdr)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    out = ciphertext+tag+cntr
    #print("out:", out.hex())
    timaccop.mac_data_req(dst, PANID, 12, dsn, out)

def process_assoc(pkt, data):
    TagInfo = namedtuple('TagInfo', """
    protoVer,
    swVer,
    hwType,
    batteryMv,
    rfu1,
    screenPixWidth,
    screenPixHeight,
    screenMmWidth,
    screenMmHeight,
    compressionsSupported,
    maxWaitMsec,
    screenType,
    rfu
    """)
    ti = TagInfo._make(struct.unpack('<BQHHBHHHHHHB11s',data))
    print(ti)

    AssocInfo = namedtuple('AssocInfo', """
    checkinDelay,
    retryDelay,
    failedCheckinsTillBlank,
    failedCheckinsTillDissoc,
    newKey,
    rfu
    """)
    ai = AssocInfo(
	    checkinDelay=10000, #check each 10sec 
	    retryDelay=1000, #retry delay 1000ms
	    failedCheckinsTillBlank=2,
	    failedCheckinsTillDissoc=4,
	    newKey=masterkey,
	    rfu=bytearray(8*[0])
    )
    ai_pkt = bytearray([ PKT_ASSOC_RESP ]) + bytearray(struct.pack('<LLHH16s8s', *ai))

    send_data(pkt['src_add'], ai_pkt)

def process_checkin(pkt, data):
    CheckinInfo = namedtuple('CheckinInfo', """
    swVer,
    hwType,
    batteryMv,
    lastPacketLQI,
    lastPacketRSSI,
    temperature,
    rfu,
    """)
    ci = CheckinInfo._make(struct.unpack('<QHHBBB6s',data))
    print(ci)

    PendingInfo = namedtuple('PendingInfo', """
    imgUpdateVer,
    imgUpdateSize,
    osUpdateVer,
    osUpdateSize,
    rfu
    """)
    pi = PendingInfo(
        imgUpdateVer = 0x0000010000000011,
        imgUpdateSize = os.path.getsize(filename),
        osUpdateVer = ci.swVer,
        osUpdateSize = 0,
	    rfu=bytearray(8*[0])
    )

    pi_pkt = bytearray([ PKT_CHECKOUT ]) + bytearray(struct.pack('<QLQL8s', *pi))

    send_data(pkt['src_add'], pi_pkt)

def process_download(pkt, data):
    ChunkReqInfo = namedtuple('ChunkReqInfo', """
    versionRequested,
    offset,
    len,
    osUpdatePlz,
    rfu,
    """)
    cri = ChunkReqInfo._make(struct.unpack('<QLBB6s',data))
    print(cri)

    ChunkInfo = namedtuple('ChunkInfo', """
    offset,
    osUpdatePlz,
    rfu,
    """)
    ci = ChunkInfo(
        offset = cri.offset,
        osUpdatePlz = 0,
        rfu = 0,
    )

    with open(filename, "rb") as f:
        f.seek(cri.offset)
        fdata = f.read(cri.len)

    outpkt = bytearray([ PKT_CHUNK_RESP ]) + bytearray(struct.pack('<LBB', *ci)) + bytearray(fdata)

    print("sending chunk", len(outpkt), outpkt)

    send_data(pkt['src_add'], outpkt)


def process_pkt(pkt):
    bcast = True
    sz = pkt['length']
    if pkt['dst_add'] == b'\xff\xff': #broadcast assoc
        hdr = bytearray.fromhex("01c8")
    else:
        hdr = bytearray.fromhex("41cc")
        bcast = False
    hdr.append(pkt['dsn'])
    hdr.extend(pkt['dst_pan_id'])
    hdr.extend(pkt['dst_add'])
    if bcast:
        hdr.extend(pkt['src_pan_id'])
    hdr.extend(reversed(pkt['src_add']))

    nonce = bytearray(pkt['data'][sz-4:])
    nonce.extend(reversed(pkt['src_add']))
    nonce.extend(b'\x00')

    tag = pkt['data'][sz-8:sz-4]

    ciphertext = pkt['data'][:sz-8]

    cipher = AES.new(masterkey, AES.MODE_CCM, nonce, mac_len=4)
    cipher.update(hdr)
    plaintext = cipher.decrypt(ciphertext)
    print("rcvd_packet:", plaintext.hex())
    try:
        cipher.verify(tag)
        print("packet is authentic")
    except:
        print("data", pkt['data'].hex())
        print("hdr", hdr.hex())
        print("ciph", ciphertext.hex())
        print("nonce", nonce.hex())
        print("tag", tag.hex())
        print("packet is NOT authentic")
        return

    typ = plaintext[0]

    if typ == PKT_ASSOC_REQ:
        print("Got assoc request")
        process_assoc(pkt, plaintext[1:])
    elif typ == PKT_CHECKIN:
        print("Got checkin request")
        process_checkin(pkt, plaintext[1:])
    elif typ == PKT_CHUNK_REQ:
        print("Got chunk request")
        process_download(pkt, plaintext[1:])
    else:
        print("Unknown request", typ)

    #send response
    send_data(pkt["src_add"], 32*b"\x00")

timaccop.init(process_pkt)

timaccop.run()

ser.close()
