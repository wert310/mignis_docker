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


import argparse
import subprocess
import shlex

from ipaddr import IPv4Address, IPv4Network
from ipaddr_ext import IPv4Range

import mignis_parser
from mignis_parser import Rule, Port, PortRange

def get_docker_aliases():
    mapping = dict()
    try:
        import docker
        cli = docker.from_env()

        for net in cli.networks.list():
            mapping[net.name] = 'br-' + net.id[:12]

        for container in cli.containers.list(all=True):
            addresses = [
                IPv4Address(v['IPAddress'])
                for _,v in container.attrs['NetworkSettings']['Networks'].items()
                if v['IPAddress'] ]
            if addresses:
                mapping[container.name] = addresses if len(addresses) > 1 else addresses[0]
    except:
        print "<!> warning: docker error!"
        import traceback
        traceback.print_exc()
    return mapping

def mk_aliases(aliases):
    mapping = get_docker_aliases()
    for a in aliases:
        mapping[a.alias] = a.address
    for k,v in mapping.items():
        if not isinstance(v, list):
            v = [v]
        nv = []
        for e in v:
            nv.append(mapping.get(e,e))
        mapping[k] = nv if len(nv) > 1 else nv[0]
    return mapping

def mk_rules(rules_list, aliases, drop_first=False):
    if drop_first:
        drops = []
        accepts = []
        for rule in rules_list:
            if rule.rule_type in [Rule.DROP, Rule.REJECT]:
                drops.append(rule)
            else:
                accepts.append(rule)
        rules_list = drops + accepts
    return [ out for rule in rules_list for out in render_rule(rule, aliases) ]

def render_rule(rule, aliases):
    actions = {
        Rule.FORWARD: 'ACCEPT',
        Rule.DROP: 'DROP',
        Rule.REJECT: 'REJECT'
    }
    if rule.rule_type not in actions:
        raise RuntimeError("Unsupported rule: {}".format(rule))

    prefix = 'iptables -t filter -A MIGNIS-DOCKER'
    src, srcport = rule.src
    dst, dstport = rule.dst

    if not isinstance(src, list): src = [src]
    if not isinstance(dst, list): dst = [dst]
    if not isinstance(srcport, list): srcport = [srcport]
    if not isinstance(dstport, list): dstport = [dstport]

    rules = []

    for src, dst, srcport, dstport in [
            (s, d, sp, dp)
            for s in src for sp in srcport
            for d in dst for dp in dstport ]:

        src = aliases.get(src, src)
        dst = aliases.get(dst, dst)

        if not isinstance(src, list): src = [src]
        if not isinstance(dst, list): dst = [dst]

        for src, dst in [ (s, d) for s in src for d in dst ]:

            proto = ''
            if rule.proto:
                proto = ' -p {}'.format(rule.proto)
            else:
                if (srcport and srcport != '*') or (dstport and dstport != '*'):
                    raise RuntimeError("No protocol specified! (rule {})".format(rule))

            if src == 'local' and dst == 'local':
                raise RuntimeError("Loopback local > local rules are not supported!")

            srcfilter = ''
            if src == 'local':
                prefix = prefix.replace("MIGNIS-DOCKER", "OUTPUT")
            elif (isinstance(src, str) or isinstance(src, unicode)) and src != '*':
                srcfilter = ' -i {}'.format(src)
            elif isinstance(src, IPv4Address) or isinstance(src, IPv4Network):
                srcfilter = ' -s {}'.format(src)
            elif isinstance(src, IPv4Range):
                srcfilter = ' -m iprange --src-range {}'.format(src)

            if isinstance(srcport, Port):
                srcfilter += ' --sport {}'.format(srcport.port)
            elif isinstance(srcport, PortRange):
                srcfilter += ' -m multiport --sports {}:{}'.format(srcport.from_, srcport.to)

            dstfilter = ''
            if dst == 'local':
                prefix = prefix.replace("MIGNIS-DOCKER", "INPUT")
            elif (isinstance(dst, str) or isinstance(dst, unicode)) and dst != '*':
                dstfilter = ' -o {}'.format(dst)
            elif isinstance(dst, IPv4Address) or isinstance(dst, IPv4Network):
                dstfilter = ' -d {}'.format(dst)
            elif isinstance(dst, IPv4Range):
                dstfilter = ' -m iprange --dst-range {}'.format(dst)

            if isinstance(dstport, Port):
                dstfilter += ' --dport {}'.format(dstport.port)
            elif isinstance(dstport, PortRange):
                dstfilter += ' -m multiport --dports {}:{}'.format(dstport.from_, dstport.to)

            extrafilters = ' ' + rule.pred if rule.pred else ''
            action = ' -j ' + actions.get(rule.rule_type, '')

            rules.append(prefix + proto + srcfilter + dstfilter + extrafilters + action)

    return rules


if __name__ == '__main__':
    parser = argparse.ArgumentParser("docker_mignis - mignis for DOCKER-USER")
    parser.add_argument('--config', '-c', required=True, help="Config file")
    parser.add_argument('--execute', '-x', action="store_true", help="Execute rules")
    parser.add_argument('--stdout', '-p', action="store_true", help="Print rules on stdout")
    args = parser.parse_args()

    conf = open(args.config, 'rb')
    content = conf.read()
    parsed = mignis_parser.mignis_conf().parse_strict(content)
    aliases = mk_aliases(parsed['ALIASES'])
    options = parsed['OPTIONS'] if 'OPTIONS' in parsed else []
    custom = parsed['CUSTOM'] if 'CUSTOM' in parsed else []

    default_drop = False
    for opt in options:
        if opt.name == 'default_drop':
            default_drop = opt.value
        else:
            print "<!> warning: option not supported '{}'".format(opt.name)

    rules = mk_rules(parsed['FIREWALL'], aliases, drop_first=default_drop)

    rules = [
        'iptables -t filter -N MIGNIS-DOCKER',
        'iptables -t filter -F MIGNIS-DOCKER',
        'iptables -t filter -D DOCKER-USER -j MIGNIS-DOCKER',
        'iptables -t filter -I DOCKER-USER 1 -j MIGNIS-DOCKER',
        'iptables -t filter -I MIGNIS-DOCKER -m state --state ESTABLISHED,RELATED -j RETURN',
    ] + rules

    if default_drop:
        rules.append('iptables -t filter -A MIGNIS-DOCKER -j DROP')

    if args.stdout:
        print "="*80
        subprocess.call(['date'])
        print "---"
        print '\n'.join(rules)

    if args.execute:
        print "Applying rules..."
        for rule in rules:
            subprocess.call(shlex.split(rule))
        print "Done."
