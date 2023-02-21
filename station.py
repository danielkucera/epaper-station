import bmp2grays
import gzip
import logging
import os
import struct
import subprocess
import threading
import concurrent.futures
import traceback
import timaccop
import time
import yaml

from collections import namedtuple
from Cryptodome.Cipher import AES
from PIL import Image

# parse byte array from string
def address_formatter(value):
    return [int(addr.strip(), 16) for addr in value.split(",")]

# parse bool from string
def bool_formatter(value):
    return value in ["True", "true", 1, "1", "yes", "Yes"]

config_path = os.environ.get("CONFIG_PATH", default="./config.yaml")

# evironment variable mappings
config_mapping = {
    # path settings
    "IMAGE_DIR":                    {"env_name": "EPS_IMAGE_DIR",                   "config": "configuration.storage.imageDirectory.path"},
    "IMAGE_WORKDIR":                {"env_name": "EPS_IMAGE_WORKDIR",               "config": "configuration.storage.workingDirectory.path"},
    "CREATE_IMGDIR":                {"env_name": "EPS_CREATE_IMGDIR",               "config": "configuration.storage.imageDirectory.createIfMissing",       "env_formatter": bool_formatter},
    "CREATE_WORKDIR":               {"env_name": "EPS_CREATE_WORKDIR",              "config": "configuration.storage.workingDirectory.createIfMissing",     "env_formatter": bool_formatter},

    # hardware settings
    "PORT":                         {"env_name": "EPS_PORT",                        "config": "configuration.zigbeeConfiguration.coordinatorInterface"},

    # zigbee settings
    "MASTER_KEY":                   {"env_name": "EPS_MASTER_KEY",                  "config": "configuration.zigbeeConfiguration.masterKey"},
    "EXTENDED_ADDRESS":             {"env_name": "EPS_EXTENDED_ADDRESS",            "config": "configuration.zigbeeConfiguration.extendedAddress",          "env_formatter": address_formatter},
    "PANID":                        {"env_name": "EPS_PANID",                       "config": "configuration.zigbeeConfiguration.panId",                    "env_formatter": address_formatter},
    "CHANNEL":                      {"env_name": "EPS_CHANNEL",                     "config": "configuration.zigbeeConfiguration.channel",                  "env_formatter": int},

    # timing settings
    "CHECKIN_DELAY":                {"env_name": "EPS_CHECKIN_DELAY",               "config": "configuration.tagSetup.checkinIntervalInMs",                 "env_formatter": int},
    "RETRY_DELAY":                  {"env_name": "EPS_RETRY_DELAY",                 "config": "configuration.tagSetup.retryIntervalInMs",                   "env_formatter": int},
    "FAILED_CHECKINS_TILL_BLANK":   {"env_name": "EPS_FAILED_CHECKINS_TILL_BLANK",  "config": "configuration.tagSetup.failedCheckinsTillBlank",             "env_formatter": int},
    "FAILED_CHECKINS_TILL_DISSOC":  {"env_name": "EPS_FAILED_CHECKINS_TILL_DISSOC", "config": "configuration.tagSetup.failedCheckinsTillDisassociate",      "env_formatter": int},
}

PKT_ASSOC_REQ = (0xF0)
PKT_ASSOC_RESP = (0xF1)
PKT_CHECKIN = (0xF2)
PKT_CHECKOUT = (0xF3)
PKT_CHUNK_REQ = (0xF4)
PKT_CHUNK_RESP = (0xF5)

VERSION_SIGNIFICANT_MASK = (0x0000ffffffffffff)

HW_TYPE_42_INCH_SAMSUNG = (1)
HW_TYPE_42_INCH_SAMSUNG_ROM_VER_OFST = (0xEFF8)
HW_TYPE_74_INCH_DISPDATA = (2)
HW_TYPE_74_INCH_DISPDATA_FRAME_MODE = (3)
HW_TYPE_74_INCH_DISPDATA_ROM_VER_OFST = (0x008b)
HW_TYPE_ZBD_EPOP50 = (4)
HW_TYPE_ZBD_EPOP50_ROM_VER_OFST = (0x008b)
HW_TYPE_ZBD_EPOP900 = (5)
HW_TYPE_ZBD_EPOP900_ROM_VER_OFST = (0x008b)
HW_TYPE_29_INCH_DISPDATA = (6)
HW_TYPE_29_INCH_DISPDATA_FRAME_MODE = (7)
HW_TYPE_29_INCH_DISPDATA_ROM_VER_OFST = (0x008b)
HW_TYPE_29_INCH_ZBS_026 = (8)
HW_TYPE_29_INCH_ZBS_026_FRAME_MODE = (9)
HW_TYPE_29_INCH_ZBS_025 = (10)
HW_TYPE_29_INCH_ZBS_025_FRAME_MODE = (11)
HW_TYPE_29_INCH_ZBS_033_BW = (12)
HW_TYPE_29_INCH_ZBS_033_BW_FRAME_MODE = (13)
HW_TYPE_154_INCH_ZBS_033 = (18)
HW_TYPE_154_INCH_ZBS_033_FRAME_MODE = (19)
HW_TYPE_42_INCH_ZBS_026 = (28)
HW_TYPE_42_INCH_ZBS_026_FRAME_MODE = (29)
HW_TYPE_29_INCH_ZBS_ROM_VER_OFST = (0x008b)

HW_TYPE_74_INCH_BWR = (40)
HW_TYPE_74_INCH_BWR_ROM_VER_OFST = (0x0160)
HW_TYPE_58_INCH_BWR = (41)
HW_TYPE_58_INCH_BWR_ROM_VER_OFST = (0x0160)
HW_TYPE_42_INCH_BWR = (42)
HW_TYPE_42_INCH_BWR_ROM_VER_OFST = (0x0160)


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

AssocInfo = namedtuple('AssocInfo', """
checkinDelay,
retryDelay,
failedCheckinsTillBlank,
failedCheckinsTillDissoc,
newKey,
rfu
""")

CheckinInfo = namedtuple('CheckinInfo', """
swVer,
hwType,
batteryMv,
lastPacketLQI,
lastPacketRSSI,
temperature,
rfu,
""")

PendingInfo = namedtuple('PendingInfo', """
imgUpdateVer,
imgUpdateSize,
osUpdateVer,
osUpdateSize,
nextCheckinDelay,
rfu
""")

ChunkReqInfo = namedtuple('ChunkReqInfo', """
versionRequested,
offset,
len,
osUpdatePlz,
rfu,
""")

ChunkInfo = namedtuple('ChunkInfo', """
offset,
osUpdatePlz,
rfu,
""")

logging.basicConfig(format='%(asctime)s %(message)s')
logger = logging.getLogger(__name__)

dsn = 0
checkin_devices = {}


def print(*args):
    msg = ""
    for arg in args:
        msg += str(arg) + " "
    logger.warning(msg)


# get element from dict by path
def get_element_by_path(object, keys):
    if keys:
        return get_element_by_path(object[keys[0]], keys[1:])
    return object

# generate config object from config mapping and config file path
def load_config(config_mapping, config_path):
    temp_config = {}
    # catch missing or invalid config file
    if not os.path.isfile(config_path):
        print(f"config file does not exist ({config_path})")
        os._exit(4)
    raw_config = {}
    # load configuration file from config.json
    with open(config_path, 'r') as f:
        try:
            raw_config = yaml.load(f, yaml.Loader)
        except ValueError as err:
            print(f"config file ({config_path}) is not valid. ({err})")
            os._exit(5)
        except yaml.scanner.ScannerError as err:
            print(f"config file ({config_path}) is not valid. ({err})")
            os._exit(6)
            
    for key in config_mapping:
        element = config_mapping[key]
        env_value = None
        env_formatter = None
        env_name = None
        if "env_formatter" in element:
            env_formatter = element["env_formatter"]
        if "env_name" in element:
            env_name = element["env_name"]

        if env_name:
            env_value = os.environ.get(env_name)
        if env_value != None:
            if env_formatter != None:
                temp_config[key] = env_formatter(env_value)
            else:
                temp_config[key] = env_value
            continue
        temp_config[key] = get_element_by_path(raw_config,element["config"].split("."))
    return temp_config


def exit(exitCode=0):
    bmp_evt.set()
    bmp_thr.join()
    print('Station stopped')
    os._exit(exitCode)


def decrypt(hdr, enc, tag, nonce):
    cipher = AES.new(masterkey, AES.MODE_CCM, nonce, mac_len=4)
    cipher.update(hdr)
    plaintext = cipher.decrypt(enc)
    # print("rcvd_packet:", plaintext.hex())
    # print("rcvhdr:", hdr.hex())
    try:
        cipher.verify(tag)
        return plaintext
    except:
        return None


def send_data(dst, data):
    global dsn
    dsn += 1
    if dsn > 255:
        dsn = 0
    hdr = bytearray.fromhex("41cc")
    hdr.append(dsn)
    hdr.extend(config['PANID'])
    hdr.extend(reversed(dst))
    hdr.extend(config['EXTENDED_ADDRESS'])
    # print("hdr:", hdr.hex())

    cntr = int(time.time())
    cntrb = struct.pack('<L', cntr)

    nonce = bytearray(cntrb)
    nonce.extend(config['EXTENDED_ADDRESS'])
    nonce.append(0)
    # print("nonce:", nonce.hex())

    cipher = AES.new(masterkey, AES.MODE_CCM, nonce, mac_len=4)
    cipher.update(hdr)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    out = ciphertext+tag+cntrb
    timaccop.mac_data_req(dst, config['PANID'], 12, dsn, out)


def process_assoc(pkt, data):
    ti = TagInfo._make(struct.unpack('<BQHHBHHHHHHB11s', data))
    print(ti)

    ai = AssocInfo(
        checkinDelay=config['CHECKIN_DELAY'],
        retryDelay=config['RETRY_DELAY'],
        failedCheckinsTillBlank=config['FAILED_CHECKINS_TILL_BLANK'],
        failedCheckinsTillDissoc=config['FAILED_CHECKINS_TILL_DISSOC'],
        newKey=masterkey,
        rfu=bytearray(8*[0])
    )
    print(ai)
    ai_pkt = bytearray([PKT_ASSOC_RESP]) + \
        bytearray(struct.pack('<LLHH16s8s', *ai))

    send_data(pkt['src_add'], ai_pkt)


def get_tmp_files(client):
    tmp_files = os.listdir(config['IMAGE_WORKDIR'])
    tmp_files = [x for x in tmp_files if x.startswith(
        bytes(client).hex().upper())]
    tmp_files = [os.path.join(config['IMAGE_WORKDIR'], x) for x in tmp_files]
    return tmp_files


def prepare_image(client, compressionSupported):
    is_bmp = False
    base_name = os.path.join(config['IMAGE_DIR'], bytes(client).hex())
    filename = base_name + ".png"
    print("Reading image file:" + base_name + ".bmp/.png")
    if os.path.isfile(filename):
        print("Using .png file")
    elif os.path.isfile(base_name + ".bmp"):
        is_bmp = True
        filename = base_name + ".bmp"
        print("Using .bmp file")
    else:
        print("No Image file available")
        return (0, 0)

    modification_time = os.path.getmtime(filename)
    creation_time = os.path.getctime(filename)
    # This uses the mofidication time of the image to look for the newest one
    imgVer = int(modification_time) << 32 | int(creation_time)

    # also use the MAC in case 1 images are created within 1 second
    file_conv = os.path.join(config['IMAGE_WORKDIR'], bytes(
        client).hex().upper() + "_" + str(imgVer) + ".bmp")

    tmp_files = get_tmp_files(client)
    tmp_files = [x for x in tmp_files if x != file_conv]

    if not os.path.isfile(file_conv):
        if is_bmp:
            bmp2grays.convertImage(1, "1bppR", filename, file_conv)
        else:
            f = os.path.join(config['IMAGE_WORKDIR'], "tempConvert_{}.bmp".format(
                bytes(client).hex().upper()))
            Image.open(filename).convert("RGB").save(f)
            bmp2grays.convertImage(1, "1bppR", f, file_conv)
            os.unlink(f)

        if compressionSupported == 1:
            file = open(file_conv, "rb")
            data = file.read()
            file.close()
            compressed_data = gzip.compress(data)
            file = open(file_conv, "wb")
            file.write(compressed_data)
            file.close()
            print("Size before compression: " + str(len(data)) +
                  " compressed: " + str(len(compressed_data)))

    for f in tmp_files:
        print('cleanup: {}'.format(f))
        os.unlink(f)

    imgLen = os.path.getsize(file_conv)
    return (imgVer, imgLen)


def get_firmware_offset(hwType):
    if hwType == HW_TYPE_74_INCH_BWR:
        return HW_TYPE_74_INCH_BWR_ROM_VER_OFST
    if hwType == HW_TYPE_58_INCH_BWR:
        return HW_TYPE_58_INCH_BWR_ROM_VER_OFST
    if hwType == HW_TYPE_42_INCH_SAMSUNG:
        return HW_TYPE_42_INCH_SAMSUNG_ROM_VER_OFST
    if hwType == HW_TYPE_74_INCH_DISPDATA:
        return HW_TYPE_74_INCH_DISPDATA_ROM_VER_OFST
    if hwType == HW_TYPE_74_INCH_DISPDATA_FRAME_MODE:
        return HW_TYPE_74_INCH_DISPDATA_ROM_VER_OFST
    if hwType == HW_TYPE_29_INCH_DISPDATA:
        return HW_TYPE_29_INCH_DISPDATA_ROM_VER_OFST
    if hwType == HW_TYPE_29_INCH_DISPDATA_FRAME_MODE:
        return HW_TYPE_29_INCH_DISPDATA_ROM_VER_OFST
    if hwType == HW_TYPE_ZBD_EPOP50:
        return HW_TYPE_ZBD_EPOP50_ROM_VER_OFST
    if hwType == HW_TYPE_ZBD_EPOP900:
        return HW_TYPE_ZBD_EPOP900_ROM_VER_OFST
    if hwType == HW_TYPE_29_INCH_ZBS_026 or hwType == HW_TYPE_29_INCH_ZBS_026_FRAME_MODE or hwType == HW_TYPE_29_INCH_ZBS_025 or hwType == HW_TYPE_29_INCH_ZBS_025_FRAME_MODE or hwType == HW_TYPE_154_INCH_ZBS_033 or hwType == HW_TYPE_154_INCH_ZBS_033_FRAME_MODE or hwType == HW_TYPE_42_INCH_ZBS_026 or hwType == HW_TYPE_42_INCH_ZBS_026_FRAME_MODE:
        return HW_TYPE_29_INCH_ZBS_ROM_VER_OFST


def prepare_firmware(hwType):
    filename = os.path.join(config['IMAGE_DIR'], 'UPDT{0:0{1}X}.BIN'.format(hwType, 4))

    print("Reading firmware file:", filename)

    if not os.path.isfile(filename):
        print("No Firmware file available")
        return (0, 0)

    f = open(filename, mode='rb')
    f.seek(get_firmware_offset(hwType))
    firmwareVersionData = f.read(8)
    f.close()

    osVer = int.from_bytes(firmwareVersionData,
                           "little") & VERSION_SIGNIFICANT_MASK | hwType << 48
    osLen = os.path.getsize(filename)

    return (osVer, osLen)


def get_image_data(imgVer, offset, length):
    filename = os.path.join(config['IMAGE_WORKDIR'], imgVer + ".bmp")
    print("Reading image file:", filename)

    f = open(filename, mode='rb')
    f.seek(offset)
    image_data = f.read(length)
    f.close()

    return image_data


def get_fw_data(hwType, offset, length):
    filename = os.path.join(config['IMAGE_DIR'], 'UPDT{0:0{1}X}.BIN'.format(hwType, 4))
    print("Reading firmware file:", filename)

    f = open(filename, mode='rb')
    f.seek(offset)
    fw_data = f.read(length)
    f.close()

    return fw_data


def cleanup_checkin_devices_context():
    bmp_files = [x for x in os.scandir(
        config['IMAGE_DIR']) if x.is_file() and x.name.endswith('.bmp')]
    # clear all coIMAGE_DIRntexts that have no image file on disk
    remaining = list(checkin_devices.keys() -
                     [x.name.split('.')[0] for x in bmp_files])
    for n in remaining:
        del checkin_devices[n]


def process_checkin(pkt, data):
    ci = CheckinInfo._make(struct.unpack('<QHHBBB6s', data))

    print(ci)

    imgVer = 0
    imgLen = 0

    try:
        imgVer, imgLen = prepare_image(pkt['src_add'], ci.rfu[0])
    except Exception as e:
        print("Unable to prepare image data for client", pkt['src_add'])
        print(e)

    osVer = 0
    osLen = 0
    checkin_devices[bytes(pkt['src_add']).hex()] = ci.rfu[0]
    cleanup_checkin_devices_context()

    try:
        osVer, osLen = prepare_firmware(ci.hwType)
    except Exception as e:
        print("Unable to prepare firmware data for client", pkt['src_add'])
        print(e)

    pi = PendingInfo(
        imgUpdateVer=imgVer,
        imgUpdateSize=imgLen,
        osUpdateVer=osVer,
        osUpdateSize=osLen,
        nextCheckinDelay=0,
        rfu=bytearray(4*[0])
    )
    print(pi)

    pi_pkt = bytearray([PKT_CHECKOUT]) + \
        bytearray(struct.pack('<QLQLL4s', *pi))

    send_data(pkt['src_add'], pi_pkt)


def process_download(pkt, data):
    cri = ChunkReqInfo._make(struct.unpack('<QLBB6s', data))
    print(cri)

    ci = ChunkInfo(
        offset=cri.offset,
        osUpdatePlz=cri.osUpdatePlz,
        rfu=0,
    )
    print(ci)

    try:
        if ci.osUpdatePlz:
            fdata = get_fw_data(cri.versionRequested >>
                                48, cri.offset, cri.len)
        else:
            fdata = get_image_data(bytes(pkt['src_add']).hex().upper(
            ) + "_" + str(cri.versionRequested), cri.offset, cri.len)
    except Exception as e:
        print("Unable to get data for version", cri.versionRequested)
        print(e)
        return

    outpkt = bytearray([PKT_CHUNK_RESP]) + \
        bytearray(struct.pack('<LBB', *ci)) + bytearray(fdata)

    print("sending chunk", len(outpkt), outpkt[:10].hex(), "...")

    send_data(pkt['src_add'], outpkt)


def generate_pkt_header(pkt):  # hacky- timaccop cannot provide header data
    bcast = True
    if pkt['dst_add'] == b'\xff\xff':  # broadcast assoc
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

    return hdr


def process_pkt(pkt):
    hdr = generate_pkt_header(pkt)

    if len(pkt['data']) < 10:
        print("Received a too short paket")
        print("data", pkt['data'].hex())
        return

    nonce = bytearray(pkt['data'][-4:])
    nonce.extend(reversed(pkt['src_add']))
    nonce.extend(b'\x00')

    tag = pkt['data'][-8:-4]

    ciphertext = pkt['data'][:-8]

    plaintext = decrypt(hdr, ciphertext, tag, nonce)
    if not plaintext:
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


def prepare_image_onchange(filepath):
    dev = [x for x in bytearray.fromhex(
        os.path.basename(filepath).split('.')[0])]
    if bytes(dev).hex() in checkin_devices:
        return prepare_image(dev, checkin_devices[bytes(dev).hex()])
    else:
        return (0, 0)


bmp_data = {}


def bmp_poller(evt):
    while not evt.wait(1):
        bmp_files = [x for x in os.scandir(
            config['IMAGE_DIR']) if x.is_file() and x.name.endswith('.bmp')]
        bmp_files_found = []
        for bmp_file in bmp_files:
            if bmp_file.name in bmp_data:
                # file is in data and directory
                s = bmp_file.stat()
                if s.st_mtime != bmp_data[bmp_file.name].st_mtime:
                    print(f'changed file {bmp_file.name}')
                    bmp_data[bmp_file.name] = s
                    bmp_files_found.append(bmp_file.name)
            else:
                # file is not in data but in directory --> new one
                bmp_data[bmp_file.name] = bmp_file.stat()
                print(f'new file {bmp_file.name}')
                bmp_files_found.append(bmp_file.name)
        for old_file in bmp_data.keys() - [x.name for x in bmp_files]:
            # garbage collection for files no more on disc but in bmp_data
            print(f'drop file {old_file}')
            del bmp_data[old_file]
        if len(bmp_files_found) > 0:
            # limit workers to one as bmp2grays uses global variables
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                bmp_files_udpated = {executor.submit(prepare_image_onchange, os.path.join(
                    config['IMAGE_DIR'], bmp_name)): bmp_name for bmp_name in bmp_files_found}
                for bmp_file_updated in concurrent.futures.as_completed(bmp_files_udpated):
                    bfup = bmp_files_udpated[bmp_file_updated]
                    try:
                        data = bmp_file_updated.result()
                    except Exception as exc:
                        print(f'{bfup} raised an exception:')
                        traceback.print_exception(exc)
                    else:
                        print(f'{bfup} processed {data}')
    print('bmp_poller exit now')

config = load_config(config_mapping, config_path)

if not os.path.exists(config['IMAGE_DIR']):
    if config['CREATE_IMGDIR']:
        os.makedirs(config['IMAGE_DIR'])
    else:
        print(f"configured image directory ({config['IMAGE_DIR']}) does not exist.")
        os._exit(24)

if not os.path.exists(config['IMAGE_WORKDIR']):
    if config['CREATE_WORKDIR']:
        os.makedirs(config['IMAGE_WORKDIR'])
    else:
        print(f"configured working directory ({config['IMAGE_WORKDIR']}) does not exist.")
        os._exit(25)

masterkey = bytearray.fromhex(config['MASTER_KEY'])

try:
    timaccop.init(config['PORT'], config['PANID'], config['CHANNEL'], config['EXTENDED_ADDRESS'], process_pkt)
except Exception as e:  # graceful exit on missing or misconfigured coordinator stick
    print(
        f"Coordinator init failed. (Wrong interface configured ({config['PORT']}), coordinator not properly connected or missing dialout privileges?)")
    os._exit(29) # not using exit function, we have not initialized yet

bmp_evt = threading.Event()
bmp_thr = threading.Thread(target=bmp_poller, args=(bmp_evt,))

bmp_thr.start()

print("Station started")

try:
    timaccop.run()
except KeyboardInterrupt:
    print("stopped by SIGINT")
    exit(0)
except Exception as e:
    print("Zigbee coordinator malfunction. (Stick removed or damaged?)")
    exit(41)
