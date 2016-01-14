import sys
from time import sleep
import splunklib.results as results
import ConfigParser
import splunklib.client as client
import re
from phase2 import getHarvesterSuspects

Config = ConfigParser.ConfigParser()
Config.read ("./config")

# The buffer of potential active scans as we collect more information
scans = {}

appStats={
    "numNonscans":0, # number of non-scan packets dropped
    "numScans":0 # number of scan packets observed.
}


# The interval (in seconds) which we perform housekeeping: detecting the conclusion of scan events, and purging one-off events not meeting scan threshold,
PURGE_INTERVAL_SECONDS = 60*60

# number of rejected packets for a given SRC and DST that constitutes a scan event being in progress.
PACKETS_PER_MINUTE_SCAN_THRESHOLD = 5

# number of seconds after last packet that must elapse before we consider a scan to be "over".
# Keep in mind there's no size fits all for a scan. A scan that checks one port per hour is entirely possible and we would miss it if our threshold values are too low.
SCAN_ENDED_AFTER = 60*5


configMap={"default":{"default":"default"}}

def ConfigSectionMap(section):
    dict1 = {}
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                print "WARNING: skipped configuration file item: %s" % option
        except:
            print("ERROR: While processing configuration file. Exception on %s!" % option)
            dict1[option] = None
    return dict1


def getAllConfigs ():
    # TODO: use a foreach loop to iterate through config sections.
    configMap["splunk"] = ConfigSectionMap("splunk")
    configMap["phase1"] = ConfigSectionMap("phase1")
    configMap["phase2"] = ConfigSectionMap("phase2")
    return configMap


def isServiceGood (serviceObject):
    # To determine if it's a good connection, iterate through installed apps. If none or no search then consider it a bad connection.
    for thisApp in service.apps:
        if thisApp.name == "search":
            return True
    return False


def getPacketAttribute (packetDict,desiredAttribute):
    return packetDict[desiredAttribute]
    # If we start using attributes that aren't nicely parsed out by Splunk and returned in the dict, we can augment this function with regex extractors.


# OrderedDict([('DPT', '5678'), ('DST', 'derp:derp:derp:derp:derp:derp:derp:derp'), ('IN', 'cm'), ('IPT_OP', 'DROP'), ('SPT', '46444'), ('SRC', 'derp:derp:derp:derp:derp:derp:derp:derp'), ('_bkt', 'main~49~derp'), ('_cd', '49:29508709'), ('_indextime', '1452263408'), ('_kv', '1'), ('_raw', 'derp'), ('_serial', '97'), ('_si', ['my.host.name.com', 'main']), ('_sourcetype', 'syslog'),
#
# *** Important *** We expect scan packet to be sent to this function in order of oldest to newest.
#
def saveOrUpdateScan(result):

    packetKey = getPacketAttribute(result,"SRC") + "-" + getPacketAttribute(result,"DST")

    # "now" meaning the time of the current packet.
    timeNowRaw = getPacketAttribute(result,"_time")
    timeNowEpoch = float(getPacketAttribute(result,"epoch_time"))

    # How many seconds have elapsed since first packet of this scan observed? Will be denominator so 0 becomes 1
    # anchor case
    elapsedThisScan = 1

    # Calculate elapsed based on given information.
    if (packetKey in scans):
        elapsedThisScan = timeNowEpoch - scans[packetKey]["startTimeEpoch"]
        # Make sure its never 0 since it will be used as denominator in rate calculations.
        if (elapsedThisScan == 0):
            elapsedThisScan = 1


    # Add or update the scans record
    if (packetKey in scans):
        # print "Packet exists. Adding new data."
        scans[packetKey]["spts"].append(getPacketAttribute(result,"SPT"))
        scans[packetKey]["dpts"].append(getPacketAttribute(result,"DPT"))
        # In the next line we convert the list into a set and back to list. This effectively uniq's the list, giving us distinct count of destination ports.
        scans[packetKey]["perMinute"] = len(set(scans[packetKey]["dpts"])) / (elapsedThisScan)
        # Maintain a perMinuteMax variable to know the maximum rate of scan packets arriving.
        if "perMinuteMax" not in scans[packetKey] or scans[packetKey]["perMinute"] > scans[packetKey]["perMinuteMax"]:
            scans[packetKey]["perMinuteMax"] = scans[packetKey]["perMinute"]
        # lastSeen will be used for identifying the end of the scan event.
        scans[packetKey]["lastSeenRaw"] = timeNowRaw
        scans[packetKey]["lastSeenEpoch"] = timeNowEpoch

        # Check and see if we need to flag this as an active scan. If active, we know to watch for end of scan.
        if "isScan" not in scans[packetKey] or scans[packetKey]["isScan"] != True:
            if scans[packetKey]["perMinute"] >= PACKETS_PER_MINUTE_SCAN_THRESHOLD:
                scans[packetKey]["isScan"] = True

    else:
        # print "New packet signature: " + packetKey
        packetDetails = {"spts":[],"dpts":[]}
        packetDetails["startTimeRaw"]=timeNowRaw
        packetDetails["startTimeEpoch"]=timeNowEpoch
        packetDetails["src"] = getPacketAttribute(result,"SRC")
        packetDetails["spts"].append(getPacketAttribute(result,"SPT"))
        packetDetails["dst"] = getPacketAttribute(result,"DST")
        packetDetails["dpts"].append(getPacketAttribute(result,"DPT"))
        packetDetails["perMinute"] = 1
        packetDetails["perMinuteMax"] = 1
        packetDetails["lastSeenRaw"] = timeNowRaw
        packetDetails["lastSeenEpoch"] = timeNowEpoch

        scans[packetKey] = packetDetails

        #print "Added new packet: "
        #print packetDetails

    # print packetKey + " rate: " + str(scans[packetKey]["perMinute"])

    return True


def scanHasEnded (scanID,timeNowRaw,timeNowEpoch):
    appStats["numScans"]+=1
    # The last observed packet marks the end of the scan event.
    scans[scanID]["endTimeRaw"]   = scans[scanID]["lastSeenRaw"]
    scans[scanID]["endTimeEpoch"] = scans[scanID]["lastSeenEpoch"]

    print "SCAN DETECTED:" \
          " startTime=" + str(scans[scanID]["startTimeRaw"]) + \
          " numPortsScanned=" + str(len(scans[scanID]["dpts"])) + \
          " SRC=" + str(scans[scanID]["src"]) + \
          " DST=" + str(scans[scanID]["dst"]) + \
          " durationSeconds=" + str(scans[scanID]["endTimeEpoch"] - scans[scanID]["startTimeEpoch"]) +  \
          " startTimeEpoch=" + str(scans[scanID]["startTimeEpoch"])

    # Pass the scan result over to the phase-2 correlator.
    getHarvesterSuspects(configMap,service,scans[scanID])

    # Mark it for recycling.
    scans[scanID]["recycle"] = True

    return True

def nonscanHasEnded(scanID):
    appStats["numNonscans"]+=1
    # Purge this item from the scans dictionary. it didn't meet qualifications to be considered a scan.
    # print "Removing packet data for packet that didn't meet scan qualifications: " + str(scans[scanID])
    scans[scanID]["recycle"] = True
    return True


# Check all active scans for signs that they have ended. This check will be called perodically during purge interval.
def checkForEndedScans(timeNowRaw,timeNowEpoch):
    for thisScanID in scans:

        timeSinceLastPacket = timeNowEpoch - scans[thisScanID]["lastSeenEpoch"]

        if "recycle" in scans[thisScanID]:
            continue

        if "isScan" not in scans[thisScanID]:
            if timeSinceLastPacket > SCAN_ENDED_AFTER:
                nonscanHasEnded(thisScanID)
            # consume the scan record and forego further processing
            continue

        if scans[thisScanID]["isScan"] != True:
            print "Confirm Scan in progress not true: " + str(scans[thisScanID]["isScan"])
            # consume the scan record and forego further processing
            continue

        # at this point we have a scan that was active at one time and may or may not still be.

        if timeSinceLastPacket > SCAN_ENDED_AFTER:
            scanHasEnded(thisScanID,timeNowRaw,timeNowEpoch)
            # consume the scan record and forego further processing
            continue

    return True

def discardTheRecyclables ():
    # TODO: Delete items marked with attribute "recycle".
    keys = scans.keys()
    for k in keys:
        if ("recycle" in scans[k]):
            del scans[k]
    return True


# Load configs from file into configMap, which is a nested map of configurations.
getAllConfigs()

splunkPassword=configMap["splunk"]['password']
splunkUsername=configMap["splunk"]['username']
splunkHost=configMap["splunk"]['host']
splunkPort=configMap["splunk"]['port']

p1searchString=ConfigSectionMap("phase1")['searchtemplate']
p1earliest=ConfigSectionMap("phase1")['earliest']
p2searchString=ConfigSectionMap("phase2")['searchtemplate'] # contains template variables that will need to be find/replaced before use.


print ("Connecting to Splunk...")

try:
    service = client.connect(host=splunkHost,
                             port=splunkPort,
                             username=splunkUsername,
                             password=splunkPassword)
except Exception as e:
    z = e
    print ("Error while connecting to " + splunkHost + ":" + str(splunkPort) + " error=" + str(z))
    sys.exit(123)

if isServiceGood (service):
    print ("Connected to Splunk server at " + splunkHost + ":" + str(splunkPort))
else:
    print ("Unable to connect to search on splunk server " + splunkHost + ":" + str(splunkPort))


# Take the search string from configuration file.
searchString = p1searchString

kwargs_export = {"earliest_time": p1earliest,
                 "latest_time": "now",
                 "search_mode": "normal",
                 "offset":"0", ## see http://dev.splunk.com/view/python-sdk/SP-CAAAER5 for great pagination example.
                 "count":"0"}

job = service.jobs.create(searchString, **kwargs_export)

maxresultrows = service.confs["limits"]["restapi"]["maxresultrows"]
print "This system is configured to return a maximum of %s results" % maxresultrows


# A normal search returns the job's SID right away, so we need to poll for completion
while True:
    while not job.is_ready():
        pass
    stats = {"isDone": job["isDone"],
             "doneProgress": float(job["doneProgress"])*100,
              "scanCount": int(job["scanCount"]),
              "eventCount": int(job["eventCount"]),
              "resultCount": int(job["resultCount"])}

    status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
              "%(eventCount)d matched   %(resultCount)d results") % stats

    sys.stdout.write(status)
    sys.stdout.flush()
    if stats["isDone"] == "1":
        sys.stdout.write("\r                                                                        ")
        break
    sleep(1)

kwargs_everything={"count":"0"}

resultsReader = results.ResultsReader(
        job.results(
                **kwargs_everything
        )
)

print ("\nIterating through firewall logs to detect scan patterns")
# Get the results and display them
itemNum=0
# unix epoch time of the last purge.
lastPurgedTime = 0
def purgeNow():
    global lastPurgedTime
    # print "Its time for a purge (of scans that have ended, and packets not meeting threshold minimums"
    checkForEndedScans(timeNowRaw,timeNowEpoch)
    discardTheRecyclables()
    lastPurgedTime = timeNowEpoch


# TODO: Pagination, as seen here: http://dev.splunk.com/view/python-sdk/SP-CAAAER5
for result in resultsReader:
    itemNum += 1

    # Toss out uninteresting records (keep as much filtering as possible in the initial splunk search not here)

    # print "Processing packet #" + str(itemNum)

    # "now" meaning the time of the current packet.
    timeNowRaw = getPacketAttribute(result,"_time")
    timeNowEpoch = float(getPacketAttribute(result,"epoch_time"))

    timeSincePurge = timeNowEpoch - lastPurgedTime

    # Store the result
    saveOrUpdateScan(result)

    # perform interval check and do a purge if its time
    if timeSincePurge > PURGE_INTERVAL_SECONDS:
        purgeNow()


# Final purge.
purgeNow()

# print "Terminating with these scans in flight: "
# for thisScanID in scans:
#     print scans[thisScanID]

print "Stats:" + str(appStats)

job.cancel()   
sys.stdout.write('\n')

