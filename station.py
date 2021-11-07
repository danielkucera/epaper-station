import timaccop 
from Crypto.Cipher import AES

masterkey = bytearray(bytes.fromhex("D306D9348E29E5E358BF2934812002C1"))

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

def process_pkt(pkt):
    sz = pkt['length']
    hdr = bytearray.fromhex("01c8")
    hdr.append(pkt['dsn'])
    hdr.extend(pkt['dst_pan_id'])
    hdr.extend(reversed(pkt['dst_add']))
    hdr.extend(pkt['src_pan_id'])
    hdr.extend(reversed(pkt['src_add']))
    #print(hdr.hex())

    nonce = bytearray(pkt['data'][sz-4:])
    nonce.extend(reversed(pkt['src_add']))
    nonce.extend(b'\x00')
    #print(nonce.hex())

    #print(pkt['data'].hex())
    tag = pkt['data'][sz-8:sz-4]
    #print(tag.hex())

    ciphertext = pkt['data'][:sz-8]
    #print(ciphertext.hex())

    cipher = AES.new(masterkey, AES.MODE_CCM, nonce, mac_len=4)
    cipher.update(hdr)
    plaintext = cipher.decrypt(ciphertext)
    print("rcvd_packet:", plaintext.hex())
    try:
        cipher.verify(tag)
        print("packet is authentic")
    except:
        print("packet is NOT authentic")
        return

    typ = plaintext[0]

    if typ == PKT_ASSOC_REQ:
        print("Got assoc request")
    else:
        print("Unknown request")

    #send response
    send_data(pkt["src_add"], 32*b"\x00")

timaccop.init(process_pkt)

timaccop.run()

ser.close()
