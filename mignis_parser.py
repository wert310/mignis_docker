#!/usr/bin/env python2

# mignis_docker - mignis for docker hosts
# Copyright (C) 2019  Lorenzo Veronese
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.


from collections import namedtuple
from operator import is_not
from functools import partial
from pprint import pprint

from ipaddr import IPv4Address, IPv4Network
from ipaddr_ext import IPv4Range
from parsec import *

################################################################################
# UTILS

filter_none = partial(filter, partial(is_not, None))

def preturn(value):
    e = StopIteration()
    e.value = value
    raise e

def option(parser, default):
    @Parser
    def option_parser(text, index):
        res = parser(text, index)
        if res.status: return res
        else: return Value.success(index, default)
    return option_parser

def permute(args, description=None):
    @Parser
    def permute_parser(text, index):
        ps = list(args)
        results = []
        while ps != []:
            for parser in ps:
                res = parser(text, index)
                if res.status:
                    results.append(res.value)
                    ps.remove(parser)
                    index = res.index
                    break
            else:
                return Value.failure(index, description) if description else res
        return Value.success(index, results)
    return permute_parser

##################################################################################
# TYPES AND GLOBALS

STAR = '*'
DOT  = '.'

class Port(namedtuple('Port', ['port'])):
    def __new__(self, port):
        p = self.check_port(port)
        return super(self, Port).__new__(self, p)

    @staticmethod
    def check_port(port):
        p = int(port)
        if p < 0 or p > (2**16-1):
            raise RuntimeError("Invalid Port Range: {}".format(p))
        return p

class PortRange(namedtuple('PortRange', ['from_', 'to'])):
    def __new__(self, portf, portt):
        pf = Port.check_port(portf)
        pt = Port.check_port(portt)
        return super(self, PortRange).__new__(self, pf, pt)

class Rule(namedtuple('Rule', ['rule_type', 'src', 'dst', 'snat', 'dnat', 'proto', 'pred'])):
    FORWARD    = '>'
    SNAT       = '>S'
    DNAT       = '>D'
    MASQUERADE = '>M'
    MDNAT      = '>MD'
    SDNAT      = '>SD'
    DROP       = '/'
    REJECT     = '//'
    BI_FORWARD = '<>'
    
    def __new__(self, rule_type, src, dst, snat=None, dnat=None, proto=None, pred=None):
        rule_type = self.check_type(rule_type, snat, dnat)
        return super(self, Rule).__new__(self, rule_type, src, dst, snat, dnat, proto, pred)
    
    @staticmethod
    def check_type(type_, snat, dnat):
        types = {'>':  Rule.FORWARD,
                 '/':  Rule.DROP,
                 '//': Rule.REJECT,
                 '<>': Rule.BI_FORWARD}
        fwtypes = [
            (lambda snat, dnat: snat and dnat and snat == DOT, Rule.MDNAT),
            (lambda snat, dnat: snat and dnat,                 Rule.SDNAT),
            (lambda snat, dnat: snat and snat != DOT,          Rule.SNAT),
            (lambda snat, dnat: snat and snat == DOT,          Rule.MASQUERADE),
            (lambda snat, dnat: dnat,                          Rule.DNAT)
        ]
        rule_type = types.get(type_)
        if not rule_type: raise RuntimeError("Invalid Rule {}".format(type_))
        if rule_type == Rule.FORWARD:
            for pred, predtype in fwtypes:
                if pred(snat, dnat):
                    rule_type = predtype
                    break
        return rule_type

Interface = namedtuple('Interface', ['alias', 'interface', 'subnet', 'options'])
Alias     = namedtuple('Alias', ['alias', 'address'])
Option    = namedtuple('Option', ['name', 'value'])
    
################################################################################
# MIGNIS PARSER

ip_addr    = regex("(:?[0-9]{1,3}\.){3}[0-9]{1,3}").parsecmap(IPv4Address)
ip_subnet  = regex("(:?[0-9]{1,3}\.){3}0/[0-9]{1,2}").parsecmap(IPv4Network)
ip_range   = regex("(:?[0-9]{1,3}\.){3}[0-9]{1,3}-(:?[0-9]{1,3}\.){3}[0-9]{1,3}")\
             .parsecmap(IPv4Range)
port       = regex("[0-9]{1,5}").parsecmap(Port)
port_range = regex("[0-9]{1,5}-[0-9]{1,5}").parsecmap(lambda s: PortRange(*s.split("-")))
star       = string("*").result(STAR)

spaces     = many(one_of("\ \t"))
endl       = string("\n")
token      = lambda p: spaces >> p << spaces 
list_of    = lambda p: symbol("(") >> sepBy1(p, symbol(",")) << symbol(")")
until_endl = (many1(none_of("\n"))).parsecmap(''.join)
symbol     = lambda s: token(string(s))
identifier = token(regex("[0-9a-zA-Z\-\_]+"))
comment    = symbol("#") >> until_endl.result(None)

addr_spec  = ip_subnet ^ ip_range ^ ip_addr ^ identifier ^ star
port_spec  = port_range ^ port ^ star
addr_port  = ((list_of(addr_spec) | addr_spec)
              + option(symbol(":") >> (list_of(port_spec) | port_spec) , STAR))

# a ([b])? (>|<>|/|//) ([c])? d (tcp)? (| ...)?
@generate
def mignis_rule():
    ipfrom = yield addr_port
    ipsnat = yield option(symbol("[") >> (symbol(".") | addr_port) << symbol("]"), None)
    rtype  = yield (symbol(">") ^ symbol("<>") ^ symbol("//") ^ symbol("/"))
    ipdnat = yield option(symbol("[") >> addr_port << symbol("]"), None)
    ipto   = yield addr_port
    proto  = yield option(identifier, None)
    rest   = yield option(symbol("|") >> until_endl, None)
    preturn (Rule(rule_type = rtype,
                  src   = ipfrom, snat = ipsnat,
                  dst   = ipto,   dnat = ipdnat,
                  proto = proto,  pred = rest))

alias     = (identifier + (list_of(addr_spec) | addr_spec)).parsecmap(lambda s: Alias(*s))
bool_opt  = (identifier + (string("yes").result(True) | string("no").result(False)))\
            .parsecmap(lambda s: Option(*s))
interface = joint(identifier, identifier,
                  (ip_subnet | string("none")).desc("subnet or `none`"),
                  many(identifier)).parsecmap(lambda s: Interface(*s))

def mignis_conf():
    def section(name, thing, optional=False):
        parser = (symbol(name) >> option(comment, None) >> many1(endl)
                  >> sepBy((comment ^ thing) << option(comment, None),
                           many1(endl))).parsecmap(filter_none)
        if optional: parser = option(parser, [])
        return parser.parsecmap(lambda s: (name, s))
    
    options    = section("OPTIONS", bool_opt, True)
    interfaces = section("INTERFACES", interface, True)
    aliases    = section("ALIASES", alias)
    firewall   = section("FIREWALL", mignis_rule)
    policies   = section("POLICIES", mignis_rule, True)
    custom     = section("CUSTOM", comment ^ until_endl, True)
    
    return (many(endl)
            >> permute([options, interfaces, aliases, firewall, policies, custom],
                "(OPTIONS | INTERFACES | ALIASES | FIREWALL | POLICIES | CUSTOM)")
            << many(endl)).parsecmap(dict)
    return (many(endl) >> options >> aliases >> firewall << many(endl))
 
################################################################################
# TESTS

if __name__ == '__main__':

    print("==== RULE ========\n")
    
    text = "192.168.1.1 [.] > [local:80] ext_ip:8989 tcp"
    rule = mignis_rule.parse(text)
    
    pprint(text)
    pprint(rule)
    
    assert rule.rule_type == Rule.MDNAT
    assert rule.src       == (IPv4Address('192.168.1.1'), STAR)
    assert rule.dst       == ('ext_ip', Port(port=8989))
    assert rule.snat      == DOT
    assert rule.dnat      == ('local', Port(port=80))
    assert rule.proto     == 'tcp'
    assert rule.pred      == None
    
    print("\n==== CONF ========\n")
    
    example_conf = """
OPTIONS
default_rules   yes
logging         no

INTERFACES
lan     eth0    10.0.0.0/24
ext     eth1    0.0.0.0/0
dummy   eth2    none         ignore
vpn     tun0    10.8.0.0/24

ALIASES
mypc            10.0.0.2
router_ext_ip   1.2.3.4
malicious_host  5.6.7.8
host_over_vpn   10.8.0.123
remote_host_1   20.20.20.1
remote_host_2   30.30.30.2
remote_host_3   40.40.40.3
remote_hosts    (remote_host_1, remote_host_2, remote_host_3)

FIREWALL
# no restrictions on outgoing connections
local > *

# ssh accessible from the outside
* > local:22  tcp

# machines inside the lan are NAT'ed (using masquerade) when communicating through ext
lan [.] > ext

# forbid the communication with a malicious host
lan / malicious_host

# dnat to mypc on port 8888
ext > [router_ext_ip:8888] mypc:8888  udp

# dnat to host_over_vpn on port 9999 with masquerade
ext [.] > [router_ext_ip:9999] host_over_vpn:9999  tcp

# allow access to port 80 and 443 on this machine
ext > local:(80, 443)  tcp

# allow only a limited set of hosts to access our vpn
remote_hosts > local:1194  udp

POLICIES
* // *  icmp
* // *  udp
* / *

CUSTOM
# log and accept packets on port 7792
-A INPUT -p tcp --dport 7792 -j LOG --log-prefix "PORT 7792 "
-A INPUT -p tcp --dport 7792 -j ACCEPT
"""
    
    conf = mignis_conf().parse_strict(example_conf)
    pprint(conf)
    
    assert len(conf['CUSTOM'])     == 2
    assert len(conf['POLICIES'])   == 3
    assert len(conf['FIREWALL'])   == 8
    assert len(conf['OPTIONS'])    == 2
    assert len(conf['ALIASES'])    == 8
    assert len(conf['INTERFACES']) == 4
    
