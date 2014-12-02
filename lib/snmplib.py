# -*- coding: UTF-8 -*-
#
# 1.0.2 Notes:
# fix utf-8 encoding bug
#
# 1.0.1 Notes:
# reraise all exceptions to caller
#
import time
import json
import netsnmp

# Please install NET-SNMP python Extension Module
# README doc:
# https://net-snmp.svn.sourceforge.net/svnroot/net-snmp/trunk/net-snmp/python/

VERSION = '1.0.2'
verbose = False


def log(message):
    if verbose:
        print '%s %s' % (time.strftime('%Y%m%d %H:%M:%S'), message)


def snmp_query(desthost, community, oid, condition=None):
    vbind = netsnmp.Varbind(oid)
    vlist = netsnmp.VarList()
    vlist.append(vbind)

    netsnmp.snmpwalk(
        vlist,
        Version=2,
        DestHost=desthost,
        Community=community,
        UseNumeric=1)
    log('oid %s have %d items before filter.' % (oid, len(vlist)))

    # result format:
    # {
    #    'INDEX': 'VALUE',
    #    'INDEX': 'VALUE',
    # }
    result = {}
    for v in vlist:
        if condition is None or condition(v.val):
            full_oid = '%s.%s' % (v.tag, v.iid)
            # INDEX is:
            # 'tag.iid' - 'oid.'
            index = full_oid[len(oid)+1:]
            result[index] = v.val

    log('oid %s have %d items after filter.' % (oid, len(result)))
    return result


def lld_format(items):
    result = {}
    result['data'] = items
    if verbose:
        return json.dumps(result, ensure_ascii=False, indent=4)
    else:
        return json.dumps(result, ensure_ascii=False)


def lld_process(hostname, community, rule):
    result = []
    # rule format:
    #    (origin_oid, [(filter_oid, filter_func)...])
    #
    # example:
    #    (
    #        '.1.3.6.1.2.1.2.2.1.2',
    #        [('.1.3.6.1.2.1.2.2.1.8', lambda x: x == '1')]
    #    )
    #
    # you can also get origin_oid without filters
    # but we recommand you using zabbix snmp lld:
    #    (
    #        '.1.3.6.1.2.1.2.2.1.2',
    #        []
    #    )
    origin_oid, filter_oids = rule

    origin_oid_items = snmp_query(hostname, community, origin_oid)
    if not origin_oid_items:
        log('origin oid %s is empty, lld finish.' % origin_oid)
        return result

    filter_oid_items_lists = []
    for oid, condition in filter_oids:
        items = snmp_query(hostname, community, oid, condition)
        filter_oid_items_lists.append(items)

    for (index, value) in origin_oid_items.iteritems():
        for items in filter_oid_items_lists:
            if index not in items.keys():
                break
        else:
            item = {}
            item['{#SNMPINDEX}'] = index
            # chardet is not good, using fixed encoding for chinese
            item['{#SNMPVALUE}'] = value.decode('gb2312').encode('utf-8')
            result.append(item)

    return result
