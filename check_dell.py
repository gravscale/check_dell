#!/usr/bin/env python
"""
SYNOPSIS

    check_dell [-h,--help] [-s, --storage] [-c, --chassis ARG1 ARG2]

DESCRIPTION

    A Nagios plugin to check Dell hardware. Designed to be used with NRPE and
    Dell's OpenManage utility: omreport. OMSA services must be started prior
    to plugins use.

    Use --help option for additional detail, regardless of PEP8 I see little
    reason in duplicating its output here."

GOTCHAS

    In some instances Nagios will not execute scripts that start with
    #!/usr/bin/env. Just change to full path of the systems python binary.

    The plugin expects a symlink of omreport in /usr/sbin, you may need to add
    one if the OMSA install script didn't. Why hard-code the path to omreport?
    Relying on the $PATH environment variable is a security concern in cases
    where the plugin is setuid root or called via sudo.

AUTHOR

    Ryan Bowlby <rbowlby83 yahoo>

LICENSE

    This script is in the public domain, free from copyrights or restrictions.

VERSION

    $Rev: 3 $
"""

import optparse
import subprocess
import sys

def check_storage():
    """ Checks Dell storage components (pdisk, vdisk, cntrl battery).

    Assigns results from omreport commands, gathered from parse_om(), to
    local lists of dicts. Combines and passes to disp_results(). Performs
    forementioned on each controller in system. omreport commands performed:

    omreport storage controller
    omreport storage pdisk controller=X
    omreport storage vdisk controller=X
    omreport storage battery
    """

    # Create list of valid controllers (i.e. ['0','1'])
    controllers = [x['ID'] for x in parse_om("storage controller", ["ID"])]

    # check pdisks, vdisks, cntrl battery for each controller
    vfilter = ["Status","Name","State"]
    pfilter = ["Status","Name","State","FailurePredicted"]
    bfilter = ["Status","Name","State"]
    for controller in controllers:
        vdisk = parse_om("storage vdisk controller=" + controller, vfilter)
        pdisk = parse_om("storage pdisk controller=" + controller, pfilter)
        battery = parse_om("storage battery controller=" + controller, bfilter)
        components = vdisk + pdisk + battery
        # Get rid of controller battery results if empty
        components = [x for x in components if x]
        # parse and display results
        disp_results(components)


def check_chassis(args):
    """ Checks Dell chassis components.

    Verifies user specified list of components to check are valid. Assigns
    results from 'omreport chassis', gathered via parse_om(), to local dict
    to bo passed to disp_results().
    """

    components = ('fans',
                  'intrusion',
                  'memory',
                  'powersupplies',
                  'processors',
                  'temperatures',
                  'voltages',
                  'hardwarelog',
                  'batteries')

    for arg in args:
        if arg.lower() == "all":
            args = ""
        elif arg.lower() not in components:
            print >> sys.stderr, '\nError: invalid chassis argument: %s' % arg
            sys.exit(1)

    # Returns dictionary in form: component:status.
    chas = parse_om("chassis",args)[0]
    disp_results(chas, chassis="True")


def parse_om(suffix, filters=""):
    """ Returns results from omreport utility as a list of dicts.

    Runs omreport with sub-command specified in param "suffix". Filters out
    lines not matching optional param "filters". Attempts to provide useful
    error output in instances where OMSA fails us.
    """

    filters = [x.lower() for x in filters]
    cmd = ["/usr/sbin/omreport"] + suffix.split()
    try:
        data = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    except OSError, e:
        print >> sys.stderr, "Error running '%s', %s" % (" ".join(cmd), e)
        sys.exit(1)

    data = data.replace(' ','').splitlines()
    result = [{}]
    for item in data:
        # Filter out useless items such as titles, blank lines.
        if ":" not in item or "SEVERITY" in item:
            continue
        key, val = item.split(":", 1)
        # Reverse chassis output to match others, ["Ok:Fans"] to ["Fans:Ok"].
        if suffix == "chassis":
            key, val = val, key
        # Limit result to those specified in filters[].
        if filters:
            if key.lower() not in filters:
                continue
        if key in result[-1]:
            result.append({})
        result[-1][key] = val

    # Sometimes omreport returns zero output if omsa services aren't started.
    if not result[0] and "battery" not in suffix:
        print >> sys.stderr, 'Error: "omreport %s" returned 0 output.' % suffix
        print >> sys.stderr, 'Is OMSA running? "srvadmin-services.sh status".'
        sys.exit(1)

    return result


def disp_results(components, chassis=""):
    """ Displays component status results, total component count, & exit status.

    Iterates through components specified in param "components", appends
    component name and state to one of three lists based on status. If any
    components are critical or warning than only those components are printed,
    otherwise all components are printed.

    Controller batteries in state "charging" are ignored as they clutter the
    Nagios status screen.
    """

    succ = []
    warn = []
    crit = []

    if chassis:
        for key in components:
            if components[key] == "Ok":
                succ.append(key + ":" + components[key])
            elif components[key] == "Critical":
                crit.append(key + ":" + components[key])
            else:
                warn.append(key + ":" + components[key])
    else:
        # components is a list of dictionaries.
        for value in components:
            if value['Status'] == 'Ok':
                succ.append("%s: Ok" % value['Name'])
            elif value['Status'] == 'Critical':
                msg = "%s in state:'%s'" % (value['Name'], value['State'])
                if value.get('FailurePredicted') == 'Yes':
                    msg += ", Failure Predicted"
                crit.append(msg)
            # All remaining statuses: non-critical, non-recoverable, etc.
            else:
                # Skip when controller battery is in state charging.
                if value['Name'].startswith("Battery"):
                   if value['State'] == "Charging" or value['State'] == "Learning":
                       continue 
                msg = "%s in state: '%s'" % (value['Name'], value['State'])
                if value.get('FailurePredicted') == 'Yes':
                    msg += ", Failure Predicted"
                warn.append(msg)

    countSuffix = " - [%s:Success, %s:Warning, %s:Critical]" %\
                  (len(succ), len(warn), len(crit))
    if crit:
        print ", ".join(crit) + ", ".join(warn) + countSuffix
        sys.exit(2)
    elif warn:
        print ", ".join(warn) + countSuffix
        sys.exit(1)
    else:
        print ", ".join(succ) + countSuffix


def main():
    """ Handles optparse usage and calls approriate check function."""

    parser = optparse.OptionParser(description=\
                "This Nagios plugin checks the health of Dell hardware. "
                "Plugin requires omreport, part of Dell's OMSA package.")

    # optparse wraps newlines and no option to override exists. As a hack
    # I inject spaces to move each example to its own line. I could
    # subclass optparse.epilog and override wrapping, but epilog only
    # exists in python versions 2.4.? and above.
    examples = optparse.OptionGroup(parser, "Examples",
                                  "check_dell -s                    "
                                  "                                 "
                                  "check_dell -c fans memory voltages"
                                  "                                 "
                                  "check_dell -c all                ")


    arguments = optparse.OptionGroup(parser, "Valid chassis args",
                                     "all fans intrusion memory "
                                     "powersupplies processors "
                                     "temperatures voltages "
                                     "hardwarelog batteries")

    parser.add_option_group(examples)
    parser.add_option_group(arguments)
    parser.add_option('-s',
                      '--storage',
                      action='store_true',
                      default=False,
                      help='check virtual and physical disks')
    parser.add_option('-c',
                      '--chassis',
                      action='store_true',
                      default=False,
                      help='check specified chassis components')

    (opts, args) = parser.parse_args()
    if not opts.chassis and not opts.storage:
        parser.print_help()
    elif opts.chassis and len(args) < 1:
        parser.error('--chassis takes one or more arguments')
    # If the checks are run together the output will be two lines.
    if opts.storage:
        check_storage()
    if opts.chassis:
        check_chassis(args)

if __name__ == '__main__':
    main()
