# epaper-station

Contains PC based controll software for epaper display protocol by @dmitrygr (http://dmitry.gr/index.php?r=05.Projects&proj=29.%20eInk%20Price%20Tags)

Needs 802.15.4 CC2531 dongle with TIMAC firmware: https://www.ti.com/tool/TIMAC

Display firmware: https://github.com/danielkucera/epaper-firmware

## Install
```
apt install python3-serial python3-crypto python3-pil
```

## Run
```
python3 station.py
```

## Usage

- to pair a display, it has to be really really close (touching the adapter with left edge)
- when the display "checks in", it will check the presence of <DISPLAY_MAC>.png in current dir, convert it to bmp and send to display
  - if the image doesn't change, the display will stay as is and checks back again in defined interval (`checkinDelay`)

## Possible improvements

- replace TIMACCoP with low level radio driver https://github.com/srhg/zag-bridge-firmware
- user python library to decode received frames e.g. https://github.com/andrewdodd/pyCCSniffer/blob/master/ieee15dot4.py
