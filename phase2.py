import sys
from time import sleep
import splunklib.results as results
import re


# Will hold a table of suspected harvesters
# key, suspectIP, suspectPort
suspects = {}
numSkippedSuspects = 0


def getPortName (portnum):
    # TODO: Lookup the service name for a given port.
    return str(portnum)

# We have a suspected packet which will need to be verified. Store it. or for now, print it for manual analysis.
def addUpdateSuspect(resultObject):

    global numSkippedSuspects

    # Don't print suspects that have a lag greater than 2 hours. This is a temporary provision to reduce the volume of phase-2 matches when addresses were used for very long periods.
    if float(resultObject["scan_delay"]) > 7200:
        numSkippedSuspects += 1
        return

    try:
        # default cases
        spt="[not tcp or udp, maybe icmp]"
        dpt="[not tcp or udp, maybe icmp]"

        # get tcp/udp port nums if available.
        if "SPT" in resultObject:
            spt=resultObject["SPT"]
        if "DPT" in resultObject:
            dpt=resultObject["DPT"]


        print "  lag=" + resultObject["scan_delay"] + "s" + \
              " @" + resultObject["_time"] + \
              " epoch=" + resultObject["epoch_time"] + \
              "  " + resultObject["SRC"] + ":" + getPortName(spt) + \
              " -> " + resultObject["DST"] + ":" + getPortName(dpt) + \
              " (" + str(numSkippedSuspects) + " packets have been skipped due to excesive scan lag)"
    except Exception as e:
        z = e
        print "<weird packet @ " + resultObject["epoch_time"] + "err=" + str(z) + ">"




# Pass the service to the module and expect summary output.
# scanDict: The dictionary containing the scan data such as ports scanned, and scan start time.
def getHarvesterSuspects (configMap,svc,scanDict):

    p2searchString=configMap["phase2"]['searchtemplate'] # contains template variables that will need to be find/replaced before use.

    # Build the search string, starting with the template from the config file.
    searchString = p2searchString
    # Search for packets sent from scan target (destination IP of the scan detected in P1) so notice the flip/flop of SRC/DST here.
    searchString = re.sub('%SRC%',scanDict["dst"],searchString)
    # Note we're adding 2 to the startTimeEpoch to help account for clock jitter and other fudge.
    searchString = re.sub('%LATEST%',str(scanDict["startTimeEpoch"] + 2),searchString)

    # print "  P2 search string: " + searchString

    kwargs_export = {"earliest_time": "-2y",
                 "latest_time": "now",
                 "search_mode": "normal",
                 "offset":"0", ## see http://dev.splunk.com/view/python-sdk/SP-CAAAER5 for great pagination example.
                 "count":"0"} ## Count has no effect. why?

    job = svc.jobs.create(searchString, **kwargs_export)

    # maxresultrows = svc.confs["limits"]["restapi"]["maxresultrows"]
    # print "This system is configured to return a maximum of %s results" % maxresultrows

    # A normal search returns the job's SID right away, so we need to poll for completion
    while True:

        # Block until search results are ready.
        while not job.is_ready():
            pass
        stats = {"isDone": job["isDone"],
                 "doneProgress": float(job["doneProgress"])*100,
                  "scanCount": int(job["scanCount"]),
                  "eventCount": int(job["eventCount"]),
                  "resultCount": int(job["resultCount"])}

        status = ("\r[Phase2Search]%(doneProgress)03.1f%%   %(scanCount)d scanned   "
                  "%(eventCount)d matched   %(resultCount)d results") % stats

        sys.stdout.write(status)
        sys.stdout.flush()
        if stats["isDone"] == "1":
            sys.stdout.write("\r                                                                             \n")
            break
        sleep(1)

    # Results are ready. Use a reader to parse through them.
    kwargs_everything={"count":"0"}
    resultsReader = results.ResultsReader(job.results(**kwargs_everything))

    print ("One or more of these packets may have triggered the scan...")
    for result in resultsReader:
        addUpdateSuspect(result)

    job.cancel()
    sys.stdout.write('\n')

