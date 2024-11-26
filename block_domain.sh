#!/bin/bash
# -*- mode:sh -*-

# Script to create or remove iptables instructions for blocking
# all ip addresses of a named domain.


show_bd_usage()
{
    echo
    echo "Usage:"
    echo "[sudo] block_domain <domain> [add|remove|show]"
    echo
    echo "Example:"
    echo "sudo block_domain facebook.com add"
    echo
    echo "Run as root if using add|remove|show argument, otherwise"
    echo "the program will return the iptables command it would use to"
    echo "add the rule."
    echo
}

show_bd_unrecognized()
{
    echo
    echo "\"$2\" is not a recognized command."
    echo "\"add\" to add a rule or rules."
    echo "\"remove\" to remove matching rule or rules."
    echo "\"show\" shows loaded rules that match."
    echo
    echo "\"add\", \"remove\", and \"show\" require root to run."
    echo
    echo "Leaving off the second parameter will show the"
    echo "iptables rules that would have been generated."
    echo
}

if [ "$#" -eq "0" ]; then
    show_bd_usage
    exit 1
fi

# Save the second argument to a global variable for *process_ip* function.
if [ "$#" -ge "2" ]; then
    echo "add remove show" | grep -q "$2"
    if [ "$?" -eq 0 ]; then
        if [ $(whoami) == "root" ]; then
            prog_op="$2"
        else
            echo "Operation \"%2\" requires root to run."
            exit 1
        fi
    else
        show_bd_unrecognized
        show_bd_usage
        exit 1
    fi
else
    prog_op="demo"
fi

# Regular expressions used in this program
re_ip='(([0-9]{1,3}\.){3}[0-9]{1,3})'
re_range=${re_ip}\\s*-\\s*${re_ip}
re_colon='[^:]:\s*(.*)'

# This function works with either _NetRange_ or _inetnum_ lines
# output from a call to _whois_ to return a beginning to end
# range of ip addresses.
get_ip_range_from_line()
{
    if [ -n "$1" ]; then
        if [[ $1 =~ $re_range ]]; then
            echo "${BASH_REMATCH[1]}-${BASH_REMATCH[3]}"
        fi
    fi
}

# The next two functions take an ip address argument, with
# which they use _whois_ to get an ip address(s) value that
# can be used in an _iptables_ call.
get_cidr()
{
    routput=$(whois $1 | grep CIDR -)
    if [ -n "$routput" ]; then
        if [[ $routput =~ $re_colon ]]; then
            echo ${BASH_REMATCH[1]}
        fi
    fi
}

get_ip_range()
{
    val=$(whois $1 | grep NetRange -)
    if [ -z "$val" ]; then
        val=$(whois $1 | grep inetnum -)
    fi

    if [ -n "$val" ]; then
        get_ip_range_from_line "$val"
    fi
}

# Used by *remove_old_rule* to identify the rule to be
# removed.  It takes an ip addresses argument (CIDR or range)
get_numbered_matching_rule()
{
    rline=$(iptables --list --line-numbers -n | grep DROP | grep $1)
    if [ -n "$rline" ]; then
        echo "$rline"
    fi
}

# The next three functions take an ip addresses argument
# (CIDR or hyphenated range) to accomplish their respective
# missions.
make_cidr_rule()
{
    echo "/sbin/iptables -I FORWARD 1 -i as+ -d $1 -j DROP"
}
make_ip_range_rule()
{
    echo "/sbin/iptables -I FORWARD 1 -i as+ -m iprange --dst-range $1 -j DROP"
}
remove_old_rule()
{
    matchedline=$(get_numbered_matching_rule $1)
    if [ -n "$matchedline" ]; then
        if [[ "$matchedline" =~ ^[0-9]+ ]]; then
            rule="iptables -D OUTPUT ${BASH_REMATCH[0]}"
            $rule
        fi
    fi
}

# After discovering that _host_ reports that Netflix has several
# ranges of ip addresses, I broke this part out to process them
# seaprately.
#
# Use this function by passing an ip address.  It will use _whois_
# to identify the range and "add", "remove", or "show" the ip address.
process_ip()
{
    ipaddr="$1"

    cidr=$(get_cidr $ipaddr)
    if [ -n "$cidr" ]; then
        ssrc="$cidr"
        scmd=$(make_cidr_rule "$cidr")
    else
        range=$(get_ip_range $ipaddr)
        if [ -n "$range" ]; then
            ssrc="$range"
            scmd=$(make_ip_range_rule "$range")
        fi
    fi

    if [ -n "$scmd" ]; then
        if [ "$prog_op" == "add" ]; then
            remove_old_rule "$ssrc"
            $scmd
        elif [ "$prog_op" == "remove" ]; then
            remove_old_rule "$ssrc"
        elif [ "$prog_op" == "show" ]; then
            get_numbered_matching_rule "$ssrc"
        elif [ "$prog_op" == "demo" ]; then
            echo "$scmd"
        fi
    fi
}


# Beginning of execution...

# Parse by line to extract ip addresses
OIFS="$IFS"
IFS=$'\n'
host_lines=($(host -t a $1))
host_lines_count=${#host_lines[*]}

ndx=0
for line in ${host_lines[@]}
do
    if [[ "$line" =~ $re_ip ]]; then
        iplist[$ndx]="${BASH_REMATCH[1]}"
        ((ndx++))
    fi
done

IFS="$OIFS"

# Now process the ip addresses, one at a time.
for ipaddr in ${iplist[@]}
do
    process_ip "$ipaddr"
done

exit 0
