import logging
import os
import re
import time

from curl import get_classification
from flask import current_app as app, render_template, request, redirect, url_for, session, Blueprint
from itsdangerous import TimedSerializer, BadTimeSignature, Signer, BadSignature
from passlib.hash import bcrypt_sha256
from sqlalchemy import ForeignKey
from werkzeug.routing import Rule

from CTFd import utils
from CTFd.models import db, Teams
from CTFd.plugins import register_plugin_asset
from models import Classification, create_db

def load(app):
    create_db(app)
    classification = Blueprint('classification', __name__, template_folder='templates')

    @classification.route('/admin/plugins/classify', methods=['GET', 'POST'])
    @utils.admins_only
    def classify():
        if request.method == 'POST':
            errors = []
            teamid = request.form['id']
            classification = request.form['classification']

            if classification == 'other':
                newclassification = request.form['newclassification']

            return '', 200
        else:
            classifications = []
            for classification in db.session.query(Classification.classification).distinct():
                classifications.append(classification[0])
            teams = []
            for team in db.session.query(Teams.name).all():
                teams.append(team[0])

            db.session.close()

            teams = sorted(teams)
            classifications = sorted(classifications)

            return render_template('manual.html', teams=teams, classifications=classifications)

    def register():
        logger = logging.getLogger('regs')
        if not utils.can_register():
            return redirect(url_for('auth.login'))
        if request.method == 'POST':
            errors = []
            name = request.form['name']
            email = request.form['email']
            password = request.form['password']

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
                    if domain == "tamu.edu":
                        classification = Classification(session['id'], get_classification(username))
                        
                    db.session.add(classification)
                    db.session.commit()
                    db.session.flush()

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
    app.register_blueprint(classification)
