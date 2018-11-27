import random
import string
import httplib2
import json
import requests

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Category, Item, User

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    jsonify,
    url_for,
    make_response,
    flash,
    session as login_session
)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

app = Flask(__name__)

engine = create_engine('sqlite:///catalog.db?check_same_thread=False')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
db_session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def show_login():
    state = ''.join(
        random.choice(
            string.ascii_uppercase + string.digits
        ) for _ in range(32)
    )
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads((h.request(url, 'GET')[1]).decode('utf-8'))

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'),
            200
        )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['email'] = data['email']
    login_session['picture'] = data['picture']

    user_id = get_user_id(login_session['email'])
    if not user_id:
        user_id = create_user()
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['email']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: ' \
              '150px;-webkit-border-radius:' \
              ' 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['email'])
    print("done!")
    return output


@app.route('/gdisconnect')
def gdisconnect():
    """Disconnect user"""
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(
            json.dumps('Current user not connected.'),
            401
        )
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User email is: ')
    print(login_session['email'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'\
          % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(
            json.dumps(
                'Failed to revoke token for given user.',
                400
            )
        )
        response.headers['Content-Type'] = 'application/json'
        return response


def create_user():
    """This method create a new user"""
    new_user = User(
        email=login_session['email'],
        picture=login_session['picture']
    )
    db_session.add(new_user)
    db_session.commit()
    user = db_session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def get_user_info(user_id):
    """This method takes the user id and return the user object"""
    user = db_session.query(User).filter_by(id=user_id).one()
    return user


def get_user_id(email):
    """This method takes the user email and return the user id"""
    try:
        user = db_session.query(User).filter_by(email=email).one()
        return user.id
    except:
        """PEP8 gives warning here (for except) but it's needed."""
        return None


@app.route('/')
@app.route('/catalog')
def show_index():
    """Show the main page (all categories and latest added items)"""
    is_in = 'email' in login_session
    print(is_in)
    categories = db_session.query(Category).all()
    latest_items = db_session.query(Item)\
        .order_by(Item.date.desc()).limit(10).all()
    return render_template('index.html',
                           categories=categories,
                           latest_items=latest_items,
                           is_in=is_in)


@app.route('/catalog/<string:category_name>/items')
def show_category(category_name):
    """Show the categories and the items for selected category"""
    is_in = 'email' in login_session
    categories = db_session.query(Category).all()
    category = db_session.query(Category).filter_by(name=category_name).one()
    items = db_session.query(Item).filter_by(category=category)\
        .order_by(Item.date.desc()).all()
    return render_template('category.html',
                           categories=categories,
                           category=category,
                           items=items,
                           is_in=is_in)


@app.route('/catalog/<string:category_name>/<string:item_name>/')
def show_item(category_name, item_name):
    """Show the page for an Item from the database and it's info"""
    category = db_session.query(Category).filter_by(name=category_name).one()
    item = db_session.query(Item)\
        .filter_by(name=item_name, category_id=category.id).one()
    return render_template('item.html', item=item)


@app.route('/catalog/new', methods=['GET', 'POST'])
def create_item():
    """Creating a new Item to the database"""
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        new_item = Item(name=request.form['name'],
                        description=request.form['description'],
                        category_id=request.form['category_id'],
                        user_id=login_session['user_id'])
        db_session.add(new_item)
        db_session.commit()
        return redirect(url_for('show_index'))
    else:
        categories = db_session.query(Category).all()
        return render_template('create_item.html', categories=categories)


@app.route('/catalog/<string:item_name>/edit', methods=['GET', 'POST'])
def edit_item(item_name):
    """Editing an Item in the database"""
    if 'email' not in login_session:
        return redirect('/login')
    item_to_be_edited = db_session.query(Item).filter_by(name=item_name).one()
    if item_to_be_edited.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are" \
               " not authorized to " \
               "edit this item. Please create your own item in order to " \
               "edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        item_to_be_edited.name = request.form['name']
        item_to_be_edited.description = request.form['description']
        item_to_be_edited.category_id = request.form['category_id']
        db_session.add(item_to_be_edited)
        db_session.commit()
        category = db_session.query(Category)\
            .filter_by(id=item_to_be_edited.category_id).one()
        return redirect(url_for('show_category', category_name=category.name))
    else:
        categories = db_session.query(Category).all()
        return render_template('edit_item.html',
                               categories=categories,
                               item=item_to_be_edited)


@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def delete_item(item_name):
    """Deleting an Item from the database"""
    if 'email' not in login_session:
        return redirect('/login')
    item_to_be_deleted = db_session.query(Item).filter_by(name=item_name).one()
    if item_to_be_deleted.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert(" \
               "'You are not authorized to delete this item. Please create" \
               " your own item in order to " \
               "delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        db_session.delete(item_to_be_deleted)
        db_session.commit()
        category = db_session.query(Category)\
            .filter_by(id=item_to_be_deleted.category_id).one()
        return redirect(url_for('show_category', category_name=category.name))
    else:
        return render_template('delete_item.html', item=item_to_be_deleted)


@app.route('/catalog.json')
def catalog_json():
    """JSON for all categories and their items"""
    categories = db_session.query(Category).all()
    categories_dicts = []
    for category in categories:
        category_dict = category.serialize
        items = db_session.query(Item).filter_by(category_id=category.id).all()
        category_dict['items'] = [i.serialize for i in items]
        categories_dicts.append(category_dict)
    return jsonify(categories=categories_dicts)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
