#!/usr/bin/env python

"""server.py -- the main flask server module"""

import dataset
import json
import random
import time
import hashlib
import datetime
import os
import dateparser
import bleach

from base64 import b64decode
from functools import wraps

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlite3 import Connection as SQLite3Connection
from werkzeug.contrib.fixers import ProxyFix

from flask import Flask
from flask import jsonify
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import Response

app = Flask(__name__, static_folder='static', static_url_path='')

db = None
lang = None
config = None

descAllowedTags = bleach.ALLOWED_TAGS + ['br', 'pre']

def login_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('error', msg='login_required'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Ensures that an user is logged in"""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('error', msg='login_required'))
        user = get_user()
        if user["isAdmin"] == False:
            return redirect(url_for('error', msg='admin_required'))
        return f(*args, **kwargs)
    return decorated_function

def get_user():
    """Looks up the current user in the database"""

    login = 'user_id' in session
    if login:
        return db['users'].find_one(id=session['user_id'])

    return None

def get_comp_score(comp_id):

    score_comp = list(db.query("SELECT total(score) FROM task_competition WHERE comp_id=:comp_id", comp_id=comp_id))[0]
    return score_comp

def get_task(comp_id, tid):
    """Finds a task with a given category and score"""

    task = db.query("SELECT t.*, c.name cat_name FROM tasks t JOIN categories c on c.id = t.category JOIN competitions comp ON comp.id=t.competition WHERE t.id = :tid AND t.competition = :comp_id",
            tid=tid, comp_id=comp_id)
    return list(task)[0]

def get_flags():
    """Returns the flags of the current user"""

    flags = db.query('''select f.task_id from flags f
        where f.user_id = :user_id''',
        user_id=session['user_id'])
    return [f['task_id'] for f in list(flags)]

def get_dates(comp_id):
    """Returns the end and start dates of current competition"""
   
    dates = db['competitions'].find_one(id=comp_id)
    return dates

def check_running(comp_id):
    """   """
    dates = get_dates(comp_id)
	 
    startDate = datetime.datetime.strptime(dates['date_start'], "%m-%d-%y %H:%M%p").date()
    endDate = datetime.datetime.strptime(dates['date_end'], "%m-%d-%y %H:%M%p").date()

    if datetime.datetime.today().date() > startDate:	
	    if datetime.datetime.today().date() < endDate:
	        db.query('UPDATE competitions SET running=1 WHERE id=:comp_id', comp_id=comp_id)

@app.route('/error/<msg>')
def error(msg):
    """Displays an error message"""

    if msg in lang['error']:
        message = lang['error'][msg]
    else:
        message = lang['error']['unknown']

    user = get_user()

    render = render_template('frame.html', lang=lang, page='error.html',
        message=message, user=user)
    return make_response(render)

def session_login(username):
    """Initializes the session with the current user's id"""
    user = db['users'].find_one(username=username)
    session['user_id'] = user['id']

@event.listens_for(Engine, "connect")
def _set_sqlite_pragma(dbapi_connection, connection_record):
    """ Enforces sqlite foreign key constrains """
    if isinstance(dbapi_connection, SQLite3Connection):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.close()

@app.route('/login', methods = ['POST'])
def login():
    """Attempts to log the user in"""

    from werkzeug.security import check_password_hash

    username = request.form['user']
    password = request.form['password']

    user = db['users'].find_one(username=username)
    if user is None:
        return redirect('/error/invalid_credentials')

    if check_password_hash(user['password'], password):
        session_login(username)
        return redirect('/competitions')

    return redirect('/error/invalid_credentials')

@app.route('/register')
def register():
    """Displays the register form"""

    userCount = db['users'].count()

    # Render template
    render = render_template('frame.html', lang=lang,
        page='register.html', login=False)
    return make_response(render)

@app.route('/register/submit', methods = ['POST'])
def register_submit():
    """Attempts to register a new user"""

    from werkzeug.security import generate_password_hash

    username = request.form['user']
    #email = request.form['email']
    password = request.form['password']

    if not username:
        return redirect('/error/empty_user')

    user_found = db['users'].find_one(username=username)
    if user_found:
        return redirect('/error/already_registered')

    isAdmin = False
    isHidden = False
    userCount = db['users'].count()

    #if no users, make first user admin
    if userCount == 0:
        isAdmin = True
        isHidden = True

    new_user = dict(username=username, #email=email,
        password=generate_password_hash(password), isAdmin=isAdmin,
        isHidden=isHidden)
    db['users'].insert(new_user)

    # Set up the user id for this session
    session_login(username)

    return redirect('/competitions')

"""@app.route('/competition/<comp_id>/')
@login_required
def tasks(comp_id):
    #Displays all the tasks of a competition in a grid

    #check_running(comp_id)
    user = get_user()
    userCount = db['users'].count()

    categories = db['categories']
    catCount = categories.count()

    flags = db['flags']

    tasks = db.query("SELECT * FROM tasks");

    tasks = list(tasks)

    grid = []

    rowCount = 0
    currentCat = 0
    currentCatCount = 0

    if len(tasks) == 0:
        row = [None] * catCount
        grid.append(row)

    for task in tasks:
        cat = task["category"] - 1

        while currentCatCount + 1 >= rowCount:
            row = [None] * catCount
            grid.append(row)
            rowCount += 1

        if currentCat != cat:
            if user['isAdmin']:
                endTask = { "end": True, "category": currentCat }
                grid[currentCatCount][currentCat] = endTask
            currentCat = cat
            currentCatCount = 0


        percentComplete = (float(flags.count(task_id=task['id'])) / userCount) * 100

        #hax for bad css (if 100, nothing will show)
        if percentComplete == 100:
            percentComplete = 99.99

        task['percentComplete'] = percentComplete

        isComplete = bool(flags.count(task_id=task['id'], user_id=user['id']))

        task['isComplete'] = isComplete

        grid[currentCatCount][cat] = task
        currentCatCount += 1

    #add the final endTask element
    if user['isAdmin']:
        if len(tasks) > 0:
            endTask = { "end": True, "category": currentCat }
            grid[currentCatCount][currentCat] = endTask

        #if any None in first row, add end task
        for i, t in enumerate(grid[0]):
            if t is None:
                endTask = { "end": True, "category": i }
                grid[0][i] = endTask


    # Render template
    render = render_template('frame.html', lang=lang, page='competition.html',
        user=user, categories=categories, grid=grid, comp_id=comp_id)
    return make_response(render)"""

@app.route('/competition/<comp_id>/')
@login_required
def competition(comp_id):
    user = get_user()
    name_team = ""
    if not user['isAdmin']:
        player_team = db.query("SELECT * FROM teams t, team_player tp WHERE tp.team_id = t.id AND t.comp_id = :comp_id AND tp.user_id = :user_id", comp_id=comp_id, user_id=session['user_id'])
        player_team = list(player_team)
        # If the normal player doesn't have a team to that competition
        if len(player_team) == 0:
            return redirect(url_for('teamsign', comp_id=comp_id))
        name_team = player_team[0]['name']

    tasks = db.query("SELECT * FROM tasks t, task_competition tc WHERE t.id = tc.task_id AND tc.comp_id = :comp_id", comp_id=comp_id)
    tasks = list(tasks)

    # Render template
    render = render_template('frame.html', lang=lang, page='competition.html',
        user=user, comp_id=comp_id, tasks=tasks, name_team=name_team)
    return make_response(render)

@app.route('/editcomp/<comp_id>', methods=['GET'])
@admin_required
def editcomp(comp_id):
    user = get_user()

    tasks_comp = db.query("SELECT * FROM tasks t LEFT OUTER JOIN task_competition tc ON t.id = tc.task_id AND tc.comp_id = :comp_id", comp_id=comp_id)
    tasks_comp = list(tasks_comp)

    render = render_template('frame.html', lang=lang, tasks_comp=tasks_comp, page='editcomp.html')
    return make_response(render)

@app.route('/editcomp/<comp_id>', methods=['POST'])
@admin_required
def editcompsubmit(comp_id):
    try:
        type_action = bleach.clean(request.form['type'], tags=[])
        task_id = bleach.clean(request.form['id'], tags=[])
    except KeyError:
        return redirect('/error/form')
    else:
        task = db.query("SELECT * FROM tasks t LEFT OUTER JOIN task_competition tc ON t.id = tc.task_id AND tc.comp_id = :comp_id WHERE t.id = :task_id", task_id=task_id, comp_id=comp_id)
        task = list(task)
        if len(task) == 0:
            result = {'success':False}
        else:
            task = task[0]
            result = {'success': True, 'id':task['id'], 'name':task['name'], 'desc':task['desc'], 'hint':task['hint'], 'category':str(task['category']), 'flag':task['flag'], 'file':task['file']}
        db.query("INSERT INTO task_competition (task_id, comp_id, score) VALUES (:task_id, :comp_id, 10)", task_id=task['id'], comp_id=comp_id)

        return jsonify(result)

@app.route('/teamsign/<comp_id>')
def teamsign(comp_id):
    user = get_user()

    render = render_template('frame.html', lang=lang, page='teamsign.html',
        user=user, comp_id=comp_id)
    return make_response(render)

@app.route('/teamsign/<comp_id>', methods=['POST'])
def teamsignsubmit(comp_id):
    if bleach.clean(request.form['check'], tags=[]) == 'newTeam':
        try:
            name = bleach.clean(request.form['name'], tags=[])
        except KeyError:
            return redirect('/error/form')
        else:
            teams = db['teams']
            hash_team = hashlib.md5(name + "competicao" + str(comp_id)).hexdigest()
            timestamp = int(time.time() * 1000)
            team = dict(
                name=name,
                hash=hash_team,
                comp_id=comp_id,
                score=0,
                timestamp=timestamp
            )
            teams.insert(team)

            team_id = teams.find_one(hash=hash_team)['id']
            team_player = db['team_player']
            team_player.insert(dict(team_id=team_id, user_id=session['user_id']))
    
    elif bleach.clean(request.form['check'], tags=[]) == 'enterTeam':
        try:
            hash_team = bleach.clean(request.form['hash'], tags=[])
        except KeyError:
            return redirect('/error/form')
        else:
            team = db.query("SELECT * FROM teams WHERE hash = :hash_team AND comp_id = :comp_id", hash_team=hash_team, comp_id=comp_id)
            team = list(team)

            if len(team) == 0:
                return redirect('/error/wrong_hash')
            else:
                team=team[0]
                team_players = db.query("SELECT * FROM team_player WHERE team_id = :team_id", team_id=team['id'])
                team_players = list(team_players)
                if len(team_players) == 3:
                    return redirect('/error/too_many_members')
                else:
                    team_playersDB = db['team_player']
                    team_playersDB.insert(dict(team_id=team['id'], user_id= session['user_id']))

    return redirect(url_for('competition', comp_id=comp_id))

@app.route('/addcat/', methods=['GET'])
@admin_required
def addcat():
    user = get_user()
    render = render_template('frame.html', lang=lang, user=user, page='addcat.html')
    return make_response(render)

@app.route('/addcat/', methods=['POST'])
@admin_required
def addcatsubmit():
    try:
        name = bleach.clean(request.form['name'], tags=[])
    except KeyError:
        return redirect('/error/form')
    else:
        categories = db['categories']
        categories.insert(dict(name=name))

        return redirect('/competitions')



@app.route('/addcompetition/', methods=['GET'])
@admin_required
def addcompetition():
    user = get_user()

    render = render_template('frame.html', lang=lang, user=user, page='addcompetition.html')
    return make_response(render)

@app.route('/addcompetition/', methods=['POST'])
@admin_required
def addcompetitionsubmit():
    try:
        name = bleach.clean(request.form['name'], tags=descAllowedTags)
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        #date_start = bleach.clean(request.form['date_start'])
    except KeyError:
        return redirect('/error/form')

    else:	

        competitions = db['competitions']
        competition = dict(
            name=name,
            desc=desc
            #date_start=date_start
    	)

        competitions.insert(competition)
        return redirect('/competitions')



#@app.route('/addtask/<comp_id>/<cat>/', methods=['GET'])
@app.route('/addtask/', methods=['GET'])
@admin_required
def addtask():
    #category = db.query('SELECT * FROM categories LIMIT 1 OFFSET :cat', cat=cat)
    category = db.query('SELECT * FROM categories')
    category = list(category)
    #category = category[0]

    user = get_user()

    render = render_template('frame.html', lang=lang, user=user,
            categories=category, page='addtask.html')
    return make_response(render)

@app.route('/addtask/', methods=['POST'])
@admin_required
def addtasksubmit():
    try:
        name = bleach.clean(request.form['name'], tags=[])
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        #competition = comp_id
        category = int(request.form['category'])
        #score = int(request.form['score'])
        hint = request.form['hint']
        flag = request.form['flag']
    except KeyError:
        return redirect('/error/form')

    else:
        tasks = db['tasks']
        #task = dict(name=name,desc=desc,competition=competition,category=category,score=score,hint=hint,flag=flag)
        task = dict(
                name=name,
                desc=desc,
                category=category,
                hint=hint,
                flag=flag)
        file = request.files['file']

        if file:
            filename, ext = os.path.splitext(file.filename)
            #hash current time for file name
            filename = hashlib.md5(str(datetime.datetime.utcnow())).hexdigest()
            #if upload has extension, append to filename
            if ext:
                filename = filename + ext
            file.save(os.path.join("static/files/", filename))
            task["file"] = filename

        tasks.insert(task)

        #return redirect(url_for('tasks', comp_id=comp_id))
        return redirect(url_for('listTasks'))

@app.route('/listTasks/', methods=['GET'])
@admin_required
def listTasks():
    category = db.query('SELECT * FROM categories')
    category = list(category)
    num_cat = len(category)

    tasks = db.query('SELECT * FROM tasks')
    tasks = list(tasks)

    temp_list = []
    task_cat = []
    for i in range(num_cat):
        temp_list.append(category[i])
        for task in tasks:
            if task['category'] == i + 1:
                temp_list.append(task)

        task_cat.append(temp_list)
        temp_list = []

    user = get_user()

    render = render_template('frame.html', lang=lang, user=user,
            task_cat=task_cat, tasks=tasks, page='listTasks.html')
    return make_response(render)

@app.route('/task/<tid>/edit', methods=['GET'])
@admin_required
def edittask(tid):
    user = get_user()

    task = db["tasks"].find_one(id=tid);
    categories = db["categories"];

    render = render_template('frame.html', lang=lang, user=user,
            categories=categories,
            page='edittask.html', task=task)
    return make_response(render)

@app.route('/task/<tid>/edit', methods=['POST'])
@admin_required
def edittasksubmit(tid):
    try:
        name = bleach.clean(request.form['name'], tags=[])
        desc = bleach.clean(request.form['desc'], tags=descAllowedTags)
        category = int(request.form['category'])
        hint = request.form['hint']
        flag = request.form['flag']
    except KeyError:
        return redirect('/error/form')

    else:
        tasks = db['tasks']
        task = tasks.find_one(id=tid)
        task['id']=tid
        task['name']=name
        task['desc']=desc
        task['category']=category
        task['hint']=hint

        #only replace flag if value specified
        if flag:
            task['flag']=flag

        file = request.files['file']

        if file:
            filename, ext = os.path.splitext(file.filename)
            #hash current time for file name
            filename = hashlib.md5(str(datetime.datetime.utcnow())).hexdigest()
            #if upload has extension, append to filename
            if ext:
                filename = filename + ext
            file.save(os.path.join("static/files/", filename))

            #remove old file
            if task['file']:
                os.remove(os.path.join("static/files/", task['file']))

            task["file"] = filename

        tasks.update(task, ['id'])
        return redirect(url_for('listTasks'))

@app.route('/task/<tid>/delete', methods=['GET'])
@admin_required
def deletetask(tid):
    tasks = db['tasks']
    task = tasks.find_one(id=tid)

    user = get_user()
    render = render_template('frame.html', lang=lang, user=user, page='deletetask.html', task=task)
    return make_response(render)

@app.route('/task/<tid>/delete', methods=['POST'])
@admin_required
def deletetasksubmit(tid):
    db['tasks'].delete(id=tid)
    return redirect(url_for('listTasks'))

@app.route('/tasks/<comp_id>/<tid>/')
@login_required
def task(comp_id, tid):
    """Displays a task of a given category with a given category and score"""

    user = get_user()

    task = get_task(comp_id, tid)
    if not task:
        return redirect('/error/task_not_found')

    flags = get_flags()
    task_done = task['id'] in flags

    solutions = db['flags'].find(task_id=task['id'])
    solutions = len(list(solutions))

    # Render template
    render = render_template('frame.html', lang=lang, page='task.html',
        task_done=task_done, login=login, solutions=solutions,
        user=user, category=task["cat_name"], comp_id=comp_id, task=task, score=task["score"])
    return make_response(render)

@app.route('/submit/<comp_id>/<task_id>/<flag>')
@login_required
def submit(comp_id, task_id, flag):
    """Handles the submission of flags"""
    user = get_user()
    user_id = user["id"]
    score_total = get_comp_score(comp_id)

    """ Get the other users on the team """
    users_team = list(db.query("SELECT user_id FROM team_player WHERE team_id = (SELECT team_id FROM team_player WHERE user_id = :user_id) AND user_id != :user_id",user_id=user_id))
    """ Get the users that solved the task """
    users_solved = list(db.query("SELECT user_id FROM flags WHERE task_id=:task_id AND comp_id=:comp_id", task_id=task_id, comp_id=comp_id))
    
    """ Check if the same player already solved the task """
    if {"user_id":user_id} in users_solved:
        return jsonify({"success":True})

    timestamp = int(time.time() * 1000)
    """ Check if other person from the team solved the task """
    solved = False
    for user in users_team:
        if user in users_solved:
            solved = True
    
    if not solved:
        team_id = list(db.query("SELECT team_id FROM team_player WHERE user_id=:user_id", user_id=user_id))[0]
        team_id = team_id["team_id"]
        score_team = list(db.query("SELECT score FROM teams WHERE id = :team_id AND comp_id=:comp_id",comp_id=comp_id, team_id=team_id, user_id=user_id))[0]
        score_team = score_team["score"]
        score_task = list(db.query("SELECT score FROM task_competition WHERE task_id=:task_id AND comp_id=:comp_id", task_id=task_id, comp_id=comp_id))[0]
        score_task = score_task["score"]
        score_team = score_team + score_task
        db.query("UPDATE teams SET score = :score_team, timestamp = :timestamp WHERE id = :team_id", score_team=score_team, team_id=team_id, timestamp=timestamp)
    db.query("INSERT INTO flags (task_id, user_id, comp_id, timestamp) VALUES (:task_id, :user_id, :comp_id, :timestamp)",task_id=task_id, comp_id=comp_id, user_id=user_id, timestamp=timestamp)
    return jsonify({"succes":True,"comp_score":score_total})

@app.route('/scoreboard/<comp_id>/')
@login_required
def scoreboard(comp_id):
    """Displays the scoreboard"""

    user = get_user()
    offset = 0
    scores_10 = db.query("SELECT * FROM teams WHERE comp_id=:comp_id ORDER BY score DESC, timestamp ASC LIMIT 10 OFFSET :offset", comp_id=comp_id, offset=offset)
    scores_10 = list(scores_10)

    # Render template
    render = render_template('frame.html', lang=lang, page='scoreboard.html',
            user=user, scores=scores_10)
    return make_response(render)


@app.route('/scoreboard.json')
def scoreboard_json():
    scores = db.query('''select u.username, ifnull(sum(f.score), 0) as score,
        max(timestamp) as last_submit from users u left join flags f
        on u.id = f.user_id where u.isHidden = 0 group by u.username
        order by score desc, last_submit asc''')

    scores = list(scores)

    return Response(json.dumps(scores), mimetype='application/json')



@app.route('/competitions')
@login_required
def competitions():
    """Displays past competitions"""

    user = get_user()
    competitions = db.query('''select * from competitions''')

    competitions = list(competitions)
    
    # Render template
    render = render_template('frame.html', lang=lang, page='competitions.html',
        user=user, competitions=competitions)
    return make_response(render)

@app.route('/delete/<postID>', methods=['POST'])
@login_required
def deleteCompetitions(postID):

    user = get_user()
    if user["isAdmin"]:
        competitions = db.query('''delete from competitions where id = ''' + postID)
        #flash('Lista deletada com sucesso')
    
    return redirect('/competitions')

@app.route('/competitions.json')
def competitions_json():
    competitions = db.query('''select * from competitions''')

    competitions = list(competitions)

    return Response(json.dumps(competitions), competitions=competitions, mimetype='application/json')

@app.route('/about')
@login_required
def about():
    """Displays the about menu"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, page='about.html',
        user=user)
    return make_response(render)


@app.route('/chat')
@login_required
def chat():
    """Displays the IRC chat"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang, page='chat.html', user=user)
    return make_response(render)


@app.route('/logout')
@login_required
def logout():
    """Logs the current user out"""

    del session['user_id']
    return redirect('/')

@app.route('/')
def index():
    """Displays the main page"""

    user = get_user()

    # Render template
    render = render_template('frame.html', lang=lang,
        page='main.html', user=user)
    return make_response(render)

"""Initializes the database and sets up the language"""

# Load config
config_str = open('config.json', 'rb').read()
config = json.loads(config_str)

app.secret_key = config['secret_key']

# Load language
lang_str = open(config['language_file'], 'rb').read()
lang = json.loads(lang_str)

# Only a single language is supported for now
lang = lang[config['language']]

# Connect to database
db = dataset.connect(config['db'])

if config['isProxied']:
    app.wsgi_app = ProxyFix(app.wsgi_app)

if __name__ == '__main__':
    # Start web server
    app.run(host=config['host'], port=config['port'],
        debug=config['debug'], threaded=True)
