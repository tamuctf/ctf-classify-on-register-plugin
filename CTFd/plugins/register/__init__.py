import os
from flask import render_template, jsonify, Blueprint, redirect, url_for, request
from sqlalchemy.sql.expression import union_all

from CTFd import utils
from CTFd.models import db, Teams, Solves, Awards, Challenges
from CTFd.plugins import register_plugin_asset
from CTFd.utils import override_template


from sqlalchemy import ForeignKey
from CTFd.models import db
import re
import requests
from HTMLParser import HTMLParser
import logging
import os
import re
import time

from flask import current_app as app, render_template, request, redirect, url_for, session, Blueprint
from itsdangerous import TimedSerializer, BadTimeSignature, Signer, BadSignature
from passlib.hash import bcrypt_sha256
from sqlalchemy import ForeignKey
from werkzeug.routing import Rule

from CTFd import utils
from CTFd.models import db, Teams
from CTFd.plugins import register_plugin_asset




import datetime
import hashlib
import json
from socket import inet_aton, inet_ntoa
from struct import unpack, pack, error as struct_error
from flask import current_app as app, render_template, request, redirect, jsonify, url_for, Blueprint, session
from passlib.hash import bcrypt_sha256
from sqlalchemy.sql import not_
from CTFd.models import db, Teams, Solves, Awards, Challenges, WrongKeys, Keys, Tags, Files, Tracking, Pages, Config, Unlocks, DatabaseError, Hints, Unlocks
from CTFd.scoreboard import get_standings
from CTFd.plugins.challenges import get_chal_class

from sqlalchemy.sql import or_

from CTFd.utils import ctftime, view_after_ctf, authed, unix_time, get_kpm, user_can_view_challenges, is_admin, get_config, get_ip, is_verified, ctf_started, ctf_ended, ctf_name, admins_only
# from CTFd.models import Hint
from CTFd.admin import admin
from CTFd.challenges import challenges
from CTFd.scoreboard import scoreboard, scores, get_standings

from flask_sqlalchemy import SQLAlchemy
from passlib.hash import bcrypt_sha256
from sqlalchemy.exc import DatabaseError
from sqlalchemy import String
from CTFd.plugins import register_plugin_asset
from CTFd import utils

#-=-=-=-=-Global-Vars-=-=-=-=-

regex = 'uid=([0-9]|[a-f])*&'
uids = []
tdElements = []


#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

#-=-=-=-=-=-Classes-=-=-=-=-=-  
class Classification(db.Model):
    __table_args__ = {'extend_existing': True} 
    id = db.Column(db.Integer, ForeignKey('teams.id'), primary_key=True)
    teamid = db.Column(db.Integer)
    classification = db.Column(db.String(128))
    other = db.Column(db.Integer)

    def __init__(self,id, classification):
        self.id = id
        self.teamid = id
        self.classification = classification

    def add_other(self, other):
        self.other = other
    
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
#-=-=-=-=-=-=-=-=-=-=-=-=-=-=-

def load(app):
    app.db.create_all()

    autoRegister = Blueprint('autoRegister', __name__, template_folder='./')
   

    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-  # This function has to be completely changed
    # -=-=-=-=A&M-Specific-=-=-=-=-  # if altering the organization is desired

    template_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'register.html')
    override_template('register.html', open(template_path).read())
                                    

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
      
    # -=-=-=-=-=-=-=-=-=-=-=-=-=-=-

    @app.route('/tamu/', methods=['GET'])
    def tamu_scores():
        if request.method == 'GET':
            classifications = Classification.query.all()
            standings = get_standings()
            teams=[]
            for i, x in enumerate(standings):
                pushed = 0
                for c in classifications:
                    if c.teamid == x.teamid and len(c.classification) == 2:
                        if c.classification[0].isupper() and c.classification[1].isdigit():

                          teams.append({'id': x.teamid, 'name': x.name, 'class': c.classification , 'score': x.score})
                          pushed = 1
                          break
                    print c.classification
            return jsonify(teams)

    @app.route('/tamuu/', methods=['GET'])
    def tamu_scores_u():
        if request.method == 'GET':
            classifications = Classification.query.all()
            standings = get_standings()
            teams=[]
            for i, x in enumerate(standings):
                pushed = 0
                for c in classifications:
                    if c.teamid == x.teamid and len(c.classification) == 2:
                        if c.classification[0]=='U' and c.classification[1].isdigit():
                          teams.append({'id': x.teamid, 'name': x.name, 'class': c.classification , 'score': x.score})
                          pushed = 1
                          break
                    print c.classification
            return jsonify(teams)

    @app.route('/tamug/', methods=['GET'])
    def tamu_scores_g():
        if request.method == 'GET':
            classifications = Classification.query.all()
            standings = get_standings()
            teams=[]
            for i, x in enumerate(standings):
                pushed = 0
                for c in classifications:
                    if c.teamid == x.teamid and len(c.classification) == 2:
                        if c.classification[0]=='G' and c.classification[1].isdigit():
                          teams.append({'id': x.teamid, 'name': x.name, 'class': c.classification , 'score': x.score})
                          pushed = 1
                          break
                    print c.classification
            return jsonify(teams)
    


    # Note: A&M students have "[text]@tamu.edu" as email addresses.
    # This can be reused if a particular group has a pattern like this.
    def register():
        logger = logging.getLogger('regs')
        if not utils.can_register():
            return redirect(url_for('auth.login'))
        if request.method == 'POST':
            errors = []
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']
            
            #-=-=-=-=-=-=-=-=- Please find a better way of doing this
            try:
                corps = request.form['corps']
            except:
                corps = "off"
            try:
                rotc = request.form['rotc']
            except:
                rotc = "off"
            try:
                dod = request.form['dod']
            except:
                dod = "off"
            #-=-=-=-=-=-=-=-=- 

            name_len = len(name) == 0
            names = Teams.query.add_columns('name', 'id').filter_by(name=name).first()
            emails = Teams.query.add_columns('email', 'id').filter_by(email=email).first()
            pass_short = len(password) == 0
            pass_long = len(password) > 128
            valid_email = re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", request.form['email'])

            if not valid_email:
                errors.append("That email doesn't look right")
            if names:
                errors.append('That team name is already taken')
            if emails:
                errors.append('That email has already been used')
            if pass_short:
                errors.append('Pick a longer password')
            if pass_long:
                errors.append('Pick a shorter password')
            if name_len:
                errors.append('Pick a longer team name')
                    #db.session.flush()
            if len(errors) > 0:
                return render_template('register.html', errors=errors, name=request.form['name'], email=request.form['email'], password=request.form['password'])
            else:
                with app.app_context():
                    team = Teams(name, email.lower(), password)
                    db.session.add(team)
                    db.session.commit()
                    db.session.flush()

                    session['username'] = team.name
                    session['id'] = team.id
                    session['admin'] = team.admin
                    session['nonce'] = utils.sha512(os.urandom(10))

                    username, domain = email.lower().split('@')
                    classification = Classification(session['id'], 'PUBLIC')
                    if domain == "tamu.edu": #Change this line to alter the domain filter for emails
                        print session
                        classification = Classification(team.id, get_classification(username))
                    else:
                        classification = Classification(team.id, "public")
                    
                    other = 0
                    if corps == "on":
                        other += 3
                    if rotc == "on":
                        other += 5
                    if dod == "on":
                        other += 7
                    

                    classification.add_other(other)
                        
                    db.session.add(classification)
                    db.session.commit()
                    #db.session.flush()

                    if utils.can_send_mail() and utils.get_config('verify_emails'):  # Confirming users is enabled and we can send email.
                        logger = logging.getLogger('regs')
                        logger.warn("[{date}] {ip} - {username} registered (UNCONFIRMED) with {email}".format(
                            date=time.strftime("%m/%d/%Y %X"),
                            ip=utils.get_ip(),
                            username=request.form['name'].encode('utf-8'),
                            email=request.form['email'].encode('utf-8')
                        ))
                        utils.verify_email(team.email)
                        db.session.close()
                        return redirect(url_for('auth.confirm_user'))
                    else:  # Don't care about confirming users
                        if utils.can_send_mail():  # We want to notify the user that they have registered.
                            utils.sendmail(request.form['email'], "You've successfully registered for {}".format(utils.get_config('ctf_name')))

            logger.warn("[{date}] {ip} - {username} registered with {email}".format(
                date=time.strftime("%m/%d/%Y %X"),
                ip=utils.get_ip(),
                username=request.form['name'].encode('utf-8'),
                email=request.form['email'].encode('utf-8')
            ))
            db.session.close()
            return redirect(url_for('challenges.challenges_view'))
        else:
            return render_template('register.html')
    

    app.view_functions['auth.register'] = register
    app.register_blueprint(autoRegister)


# -=-=-=-=-=-=-=-=-=- TAMU's Scoreboard Function -=-=-=-=-=-=-
def tamu_test():
    return "This is defined"


