import re
import requests
from HTMLParser import HTMLParser

# http://docs.python-requests.org/en/master/user/install/#install

regex = 'uid=([0-9]|[a-f])*&'
uids = []
tdElements = []

class MyHTMLParser(HTMLParser):
    def handle_starttag(self, tag, attrs):
        if tag != 'a':
            return
        attr = dict(attrs)

        m = re.search(regex, attr['href'])
        if m:
            uids.append(m.group(0)[4:-1])


class TableParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self)
        self.in_td = False

    def handle_starttag(self, tag, attrs):
        if tag == 'td':
            self.in_td = True

    def handle_data(self, data):
        if self.in_td:
            tdElements.append(data)

    def handle_endtag(self, tag):
        self.in_td = False


def get_classification(user):
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    params = (
        ('zone', 'search'),
    )

    data = [
      ('text', user),
      ('target', 'searchmailbox'),
      ('org', 'people'),
    ]

    r = requests.post('http://hdc.tamu.edu/hdcapps/ldap/index.php', headers=headers, params=params, data=data)

    # NB. Original query string below. It seems impossible to parse and
    # reproduce query strings 100% accurately so the one below is given
    # in case the reproduced version is not "correct".
    # requests.post('http://hdc.tamu.edu/hdcapps/ldap/index.php?zone=search', headers=headers, data=data)

    parser = MyHTMLParser()
    parser.feed(r.text)

    # we only need the first uid for our use case
    query = uids[0]

    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    }

    params = (
        ('zone', 'search'),
        ('uid', query),
        ('org', 'people'),
        ('text', user),
        ('target', 'searchmailbox'),
    )

    r = requests.get('http://hdc.tamu.edu/hdcapps/ldap/index.php', headers=headers, params=params)

    # NB. Original query string below. It seems impossible to parse and
    # reproduce query strings 100% accurately so the one below is given
    # in case the reproduced version is not "correct".
    # requests.get('http://hdc.tamu.edu/hdcapps/ldap/index.php?zone=search&uid=5801480fe3d66bef763e6b4507975f92&org=people&text=sandanzuki&target=searchmailbox', headers=headers)

    p = TableParser()
    p.feed(r.text)

    goal = 'tamuedupersonclassification'
    reached = False

    for element in tdElements:
        if reached:
            return element
        if goal == element:
            reached = True

