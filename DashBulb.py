from scapy.all import *
import subprocess
from flux_led import WifiLedBulb, BulbScanner
import datetime
import os
import sys


version = "1.0.3  " # assign version number for debugging
bulb = WifiLedBulb('192.168.XX.XX') # assign bulb IP
#bulb.refreshState() # refresh state to collect accurate staus
logfile = r"/home/pi/SANDBOX/Dash/logfiles.log"  # name of my log file
WHITE_MAC_ADDRESS = 'XX:XX:XX:XX:XX:XX' # enter Dash Button's MAC Address here.
testMAC = 'XX:XX:XX:XX:XX:XX'


dashButton = {
    "whiteDash" : 'XX:XX:XX:XX:XX:XX',
    "redDash" : 'XX:XX:XX:XX:XX:XX'
}

whiteBulb = (0,0,0,191)
redBulb = (15,0,0,0)





#sniff for packets sent from button press
def detect_button(pkt):
    for mac in dashButton:
        if pkt.haslayer(DHCP) and pkt[Ether].src == dashButton[mac]:
        #TODO: use switch case instead
            write_log("Button pressed: ", logfile)
            bulb.refreshState()
            #write_log (bulb.getRgbw)
            currentColor = bulb.getRgbw()
            #write_log(currentColor, logfile)
            if currentColor == whiteBulb:
                if mac == "whiteDash":
                    write_log("White bulb shut off: ", logfile)
                    bulb.setRgb(0,0,0)
                    bulb.refreshState()
                    time.sleep(2)
                elif mac == "redDash":
                    write_log("Red bulb set: ", logfile)
                    bulb.setRgb(15,0,0)
                    bulb.refreshState()
                    time.sleep(2)
            elif currentColor == redBulb:
                if mac == "redDash":
                    write_log("Red bulb shut off: ", logfile)
                    bulb.setRgb(0,0,0)
                    bulb.refreshState()
                    time.sleep(2)
                elif mac == "whiteDash":
                    write_log("White bulb set: ", logfile)
                    bulb.setWarmWhite(75)
                    bulb.refreshState()
                    time.sleep(2)
            else:
                if mac == "redDash":
                    write_log("Red bulb set: ", logfile)
                    bulb.setRgb(15,0,0)
                    bulb.refreshState()
                    time.sleep(2)
                elif mac == "whiteDash":
                    write_log("White bulb set: ", logfile)
                    bulb.setWarmWhite(75)
                    bulb.refreshState()
                    time.sleep(2)
    return

#record actions to logfile for later debugging
def write_log(text, file):
    f = open(file, 'a')           # 'a' will append to an existing file if it exists
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %I:%M:%S %p")
    f.write("{}\n".format(text + timestamp))  # write the text to the logfile and move to next line
    return


write_log("Running version:"+version, logfile)


#loops forever sniffing traffic  and call the detect function
#Sniff can run forever but would hit two packets at a time.
#Using While loop and 1 packet filter to loop forever but only grab first packet



while True:
    sniff( count=1, prn=detect_button, filter="(udp and (port 67 or 68))", store=0)
