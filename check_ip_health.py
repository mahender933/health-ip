import configparser
from datetime import datetime
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pymongo import MongoClient
import redis
from threading import Thread
from urllib3.exceptions import HTTPError
from urllib3 import ProxyManager

config = configparser.ConfigParser()
config.read(os.path.dirname(os.path.realpath(__file__)) + "/config.ini")

# create logger with 'spam_application'
logger = logging.getLogger(__name__)


def connect_redis():
    """
    Creates a redis connection.
    :return: redis connection
    """
    try:

        r = redis.StrictRedis(host=config.get('REDIS', 'HOST'), port=int(config.get('REDIS', 'PORT')),
                              password=config.get('REDIS', 'PWD'), decode_responses=True)
        r.ping()
        logger.info('Connected Redis !')
        return r

    except Exception as e:
        logger.error('Error in connecting to redis : {}'.format(e))


def connect_mongo():
    """
    Creates a mongo connection
    :return: mongo connection to a particular db
    """
    try:
        client = MongoClient('mongodb://' + config.get('MONGO', 'user') + ':' + config.get('MONGO', 'pwd') + '@' +
                             config.get('MONGO', 'host') + '/' + config.get('MONGO', 'authDB')
                             + '?readPreference=primary')
        # client = MongoClient("mongodb://localhost:27017/")
        connection = client[config.get('MONGO', 'db')]
        return connection
    except Exception as e:
        logger.error('Error in connecting to mongo : {}'.format(e))


def push_data(redis_cur, chklist, qkey):
    """
    Prepare Queue which would be listened by check_ip_health function
    :param redis_cur: Redis cursor
    :param chklist: List of all ips which needs to be checked
    :param qkey: redis key in which these ips would be pushed and this key would be listened by check_ip_health
    :return: total ips
    """
    total_count = 0
    for ip in chklist:
        proxy = 'http://' + ip['ip'].strip()
        redis_cur.lpush(qkey, proxy)
        total_count += 1
    logger.info('Pushed all data to redis')
    return total_count


def update_health(redis_cur, queue_report, cron_id, open_proxy, stat):
    """
    Updates ips health in open_proxy collection by consuming queue_report redis key, which is maintained by
    check_ip_health. It also updates good count, bad count and anon count in separate redis key.
    :param redis_cur: Redis cursor
    :param queue_report: consumes this redis key containing ips health, maintained by check_ip_health
    :param cron_id: cron_id for daily check
    :param open_proxy: mongo connection to open_proxy collection
    :param stat: dictionary having keys name for redis stats
    :return:
    """
    while True:

        response = redis_cur.brpop(queue_report, timeout=int(config.get('REDIS', 'TIMEOUT')))

        # Daily check is completed after timeout if response is still None
        if response is None:
            return

        try:
            response = json.loads(response[1])
        except Exception as e:
            logger.error("Error :{} for response {}".format(e, response))
        ip = response['ip']
        dns = response['dns']
        working = response['working']
        anon = response['anon']

        if not working:
            open_proxy.update({'ip': ip},
                              {
                                 '$inc': {'chkfcnt': 1, 'chkcnt': 1},
                                 '$set': {
                                       'status': 0,
                                       'lchkon': cron_id,
                                       'pip': '',
                                       'dns': dns,
                                       'anon': anon,
                                       'chkst': 1
                                       }

                              })
            redis_cur.incr(stat['bad'])
        else:
            open_proxy.update({'ip': ip},
                              {
                                 '$inc': {'chkcnt': 1},
                                 '$set': {
                                     'status': 1,
                                     'lchkon': cron_id,
                                     'chkfcnt': 0,
                                     'pip': '',
                                     'dns': dns,
                                     'anon': anon,
                                     'chkst': 1
                                 }
                              })
            redis_cur.incr(stat['good'])
            if not anon:
                redis_cur.incr(stat['anon'])


def get_response(ip, url):
    """
    Using aws or our server url, proxy is checked whether it is working or not and  its status
    with anonymity level is returned.
    :param ip: ip:port combination to be checked.
    :param url: aws or our server url upon which proxy would be checked.
    :return: Dictionary having status (true for http code 200 else false) and
            anon (true if proxy expose our public ip)
    """
    try:
        req = ProxyManager(ip)
        resp = req.request('GET', url, timeout=5)
        http_code = resp.status
        response = resp.data.decode('utf-8')
        anon = False
        if "<html" in response:
            http_code = 0
        elif config.get('URL', 'PUBLICIP') in response:  # server public ip
            anon = True
            http_code = 0
        elif "bind failed" in response:
            http_code = 0
        if not response:
            http_code = 0

    except HTTPError as e:
        http_code = 0
        anon = False

    except Exception as e:
        http_code = 0
        anon = False

    result = dict()
    result['status'] = True if http_code == 200 else False
    result['anon'] = True if anon else False
    return result


def check_ip_health(redis_cur, qcheck, queue_report):
    """

    :param redis_cur: redis cursor
    :param qcheck: redis key which contains all ips to be checked
    :param queue_report: redis key which maintains ips report/health
    :return:
    """
    while True:
        if not redis_cur.exists(qcheck):
            logger.info('All redis data finished')
            return

        data = redis_cur.brpop(qcheck)[1]

        # request to our server
        build_url = config.get('URL', 'SERVER')
        fchck = get_response(data, build_url)

        # request to aws server
        build_url = config.get('URL', 'AWS')
        schck = get_response(data, build_url)

        if fchck['status'] and not schck['status']:  # dns not resolved
            dns = 0
            working = True
        elif fchck['status'] and schck['status']:   # works for both cases
            dns = 1
            working = True
        else:  # not works for both or works for only aws
            dns = 0
            working = False

        # set anonymity
        if working:
            anon = 1  # not exposed
            if fchck['anon'] or schck['anon']:
                anon = 0  # exposed public Ip
        else:
            anon = 0

        output = {
            'ip': data.replace('http://', ''),
            'dns': dns,
            'working': working,
            'anon': anon
        }
        output = json.dumps(output)
        redis_cur.lpush(queue_report, output)


def log_daily_check(connection, cron_id, total, count_new, discarded, rc=None, stat=None):
    """
    Logs inserted for daily check
    :param connection: Mongo connection to a particular db
    :param cron_id: Daily check timestamp
    :param total: total proxies for which test is initiated
    :param count_new: new proxies count for which test is initiated for first time
    :param discarded: number of ips for which daily check is not initiated
    :param rc: redis cursor
    :param stat: dictionary having keys name for redis stats
    :return:
    """
    oproxy_check = connection['oProxyCheck']

    if rc:  # daily check finished
        oproxy_check.update({'started_at': cron_id, 'status': 1},
                            {'$set': {'status': 2,
                                      'goodcnt': int(rc.get(stat['good'])),
                                      'badcnt': int(rc.get(stat['bad'])),
                                      'anoncnt': int(rc.get(stat['anon'])),
                                      'finished_at': datetime.utcnow()
                                      }
                             })
        rc.delete(stat['good'], stat['bad'], stat['anon'])
        logger.info('Daily check finished .')

    else:  # daily check started
        log = {
            'started_at': cron_id,
            'total': total,  # set count of ips for which check is scheduled
            'status': 1,  # set Daily Check status to started & ongoing (i.e 1) from not started (i.e 0)
            'finished': '',
            'goodcnt': 0,
            'badcnt': 0,
            'anoncnt': 0,
            'new': count_new,  # set new ips count for which check is scheduled for first time
            'goodnew': 0,
            'discarded': discarded
        }
        object_id = oproxy_check.insert(log)
        logger.info('Daily check started for {} ips with cron id: {} and object id: {}'.format(
            total, cron_id, object_id))


def set_stats_count(r, stat):
    """
    It sets daily check good count, bad count and anon count in redis.
    :param r: redis connection cursor
    :param stat: dictionary having keys name for redis stats
    :return:
    """
    r.set(stat['good'], 0)
    r.set(stat['bad'], 0)
    r.set(stat['anon'], 0)
    logger.info('Initialised stats count in redis.')


def main():
    # set log level
    logger.setLevel(logging.DEBUG)

    # create file handler which logs even debug messages
    handler = RotatingFileHandler(config.get('LOG', 'FILE'), mode='a',
                                  maxBytes=50 * 1024 * 1024, backupCount=int(config.get('LOG', 'BACKUP')))
    handler.setLevel(logging.DEBUG)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(thread)d - %(message)s')
    handler.setFormatter(formatter)

    logger.addHandler(handler)

    db = connect_mongo()
    open_proxy = db['open_proxy']

    # update chkst flag to zero
    open_proxy.update_many({'chkst': 1}, {'$set': {'chkst': 0}})

    # update chkst flag to zero and get new proxies count which would be checked for first time
    new = open_proxy.update_many({'chkst': -1}, {'$set': {'chkst': 0}})
    new = new.modified_count

    # discarded ips which would not be tested
    discarded = open_proxy.find({'chkfcnt': 5, 'status': 0}).count()

    # get all ips except whose consecutive failure count is more or equal to 5
    chklist = open_proxy.find({'chkst': 0, 'chkfcnt': {'$lt': 5}})

    # connect to redis and get a cursor
    redis_cursor = connect_redis()

    # this queue maintains all ips for which health report is to be judged
    check_queue = config.get('REDIS', 'CHECKQ')

    # push all ips to be checked in redis queue
    push_data(redis_cursor, chklist, check_queue)

    # queue in which ips health status would be sent
    report_queue = config.get('REDIS', 'REPORTQ')

    # Threading
    thread_list = []
    for i in range(int(config.get('INSTANCES', 'LIMIT'))):
        t = Thread(target=check_ip_health, args=(redis_cursor, check_queue, report_queue))
        t.start()
        thread_list.append(t)
    logger.info('All threads for check_ip_health initiated .')

    # generate cron_id for daily check
    started_at = datetime.utcnow()

    # Log Entry for Daily Check
    total = chklist.count()
    log_daily_check(connection=db, cron_id=started_at, total=total, count_new=new, discarded=discarded)

    # Redis set goodcnt , badcnt and anoncnt
    stats = {
        'good': config.get('REDIS', 'GDCNT'),
        'bad': config.get('REDIS', 'BDCNT'),
        'anon': config.get('REDIS', 'ANCNT')
    }
    set_stats_count(redis_cursor, stats)

    # update status of ips
    health_updater = Thread(target=update_health, args=(redis_cursor, report_queue, started_at, open_proxy, stats))
    health_updater.start()
    logger.info('Initiated update health')
    thread_list.append(health_updater)
    for thread in thread_list:
        thread.join()

    # set log entry status to completed with finished timestamp and good,bad & anon stats
    # and delete count stats key in redis
    log_daily_check(connection=db, cron_id=started_at, total=None, count_new=None, discarded=None, rc=redis_cursor, stat=stats)


if __name__ == '__main__':

    main()
