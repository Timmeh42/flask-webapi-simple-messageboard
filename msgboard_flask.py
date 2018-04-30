#!/usr/bin/env python

import flask
import sqlite3
import time
import hashlib
import json
import re

# Create the application.
APP = flask.Flask(__name__)
APP.secret_key = b'asdj#$vm(Re9r8(*'


@APP.route('/')
def anon():
	#if 'username' in flask.request.cookies and 'logged_in' in flask.request.cookies and flask.request.cookies.get('logged_in') == 'true':
	if 'username' in flask.session and 'logged_in' in flask.session and flask.session['logged_in'] == 'true':
		resp = flask.make_response(flask.redirect('/msgboard'))
	else:
		resp = flask.render_template('index.html')
	return resp

@APP.route('/login', methods=['POST'])
def login():
	username = flask.request.form['username']
	password = flask.request.form['password']
	conn = sqlite3.connect('message_board.db')
	conn.row_factory = sqlite3.Row
	curs = conn.cursor()
	curs.execute('SELECT username, pass_hash, pass_salt FROM users WHERE username = ?', (username,))
	result = curs.fetchall()
	conn.close()
	if result != [] and result[0]['pass_hash'] == hashlib.sha256(bytes(password+result[0]['pass_salt'], 'utf-8')).hexdigest():
		resp = flask.make_response(flask.redirect('/msgboard'))
		#resp.set_cookie('logged_in', value='true')
		#resp.set_cookie('username', value=username)
		flask.session['username'] = username
		flask.session['logged_in'] = 'true'
		print('User {} logged in'.format(username))
	else:
		flask.flash('Login details incorrect')
		resp = flask.make_response(flask.redirect('/'))
		#resp.set_cookie('logged_in', value='false')
		#resp.set_cookie('username', value='')
		print('Failed login with username {}'.format(username))
	return resp

@APP.route('/register', methods=['POST'])
def register():
	username = flask.request.form['username']
	password = flask.request.form['password']
	
	resp = flask.make_response(flask.redirect('/'))

	if re.fullmatch('^[A-Za-z0-9_]{3,}$', username) == None:
		flask.flash('Username must be 3 or more characters and consist of letters, numbers and "_"')
	elif re.fullmatch('^[A-Za-z0-9_]{4,}$', password) == None:
		flask.flash('Password must be 4 or more characters and consist of letters, numbers and "_"')
	else:
		conn = sqlite3.connect('message_board.db')
		conn.row_factory = sqlite3.Row
		curs = conn.cursor()
		curs.execute('SELECT username FROM users WHERE username = ?', (username,))
		user_exists = curs.fetchall()
		conn.close()

		if len(user_exists) != 0:
			flask.flash('Username already exists')
		else:
			salt = hashlib.sha256(bytes(str(time.time()), 'utf-8')).hexdigest()
			pass_hashed = hashlib.sha256(bytes(password+salt, 'utf-8')).hexdigest()
			conn = sqlite3.connect('message_board.db')
			curs = conn.cursor()
			timestamp = time.time()
			curs.execute('INSERT INTO users(username, pass_hash, pass_salt) VALUES (?, ?, ?)', (username, pass_hashed, salt))
			conn.commit()
			conn.close()
			resp = flask.make_response(flask.redirect('/msgboard'))
			#resp.set_cookie('logged_in', value='true')
			#resp.set_cookie('username', value=username)
			flask.session['username'] = username
			flask.session['logged_in'] = 'true'
			print('User {} registered'.format(username))
	return resp

@APP.route('/msgboard')
def msgboard():
	messages = get_messages()
	name = 'Anonymous'
	if 'username' in flask.session and 'logged_in' in flask.session:
		name = flask.session['username']
	return flask.render_template('msgboard.html', name=name, messages=messages)

@APP.route('/db')
def db_contents():
	conn = sqlite3.connect('message_board.db')
	conn.row_factory = sqlite3.Row
	curs = conn.cursor()
	curs.execute('SELECT * FROM users')
	users = curs.fetchall()
	curs.execute('SELECT * FROM messages')
	messages = curs.fetchall()
	json_out = json.dumps({'users':[dict(u) for u in users], 'messages':[dict(m) for m in messages]})
	conn.close()
	return APP.response_class(response=json_out, status=200, mimetype='application/json')

@APP.route('/post_reply', methods=['POST'])
def post_reply():
	if flask.session['logged_in'] == 'true':
		author = flask.session['username']
		parentid = flask.request.form['replyid']
		text = flask.request.form['text']
		conn = sqlite3.connect('message_board.db')
		curs = conn.cursor()
		timestamp = time.time()
		curs.execute('SELECT id FROM users WHERE username = ?', (author,))
		userid = curs.fetchone()[0]
		curs.execute('INSERT INTO messages(parent, author, text, timestamp) VALUES (?, ?, ?, ?)', (parentid, userid, text, timestamp))
		conn.commit()
		conn.close()
		print('User {} posted reply {} to parent {}'.format(author, userid, parentid))
		messages = get_messages()
	else:
		flask.flash('You are not logged in')
	return flask.make_response(flask.redirect('/msgboard'))

@APP.route('/delete_reply', methods=['DELETE'])
def delete_reply():
	if flask.session['logged_in'] == 'true':
		conn = sqlite3.connect('message_board.db')
		curs = conn.cursor()
		delid = flask.request.args.get('deleteid')
		curs.execute('SELECT author FROM messages WHERE id = ?', (delid,))
		authorid = curs.fetchone()[0]
		curs.execute('SELECT id FROM users WHERE username = ?', (flask.session['username'],))
		userid = curs.fetchone()[0]
		if authorid == userid:
			curs.execute('DELETE FROM messages WHERE id = ?', (delid,))
			conn.commit()
			print('User {} deleted post {}'.format(flask.session['username'], delid))
		else:
			flask.flash('You are not the author of this post')
			print('User {} attempted to delete post {} but does not have permission'.format(flask.session['username'], delid))
		conn.close()
	else:
		flask.flash('You are not logged in')
	return ('', 204)

@APP.route('/edit_reply', methods=['PUT'])
def edit_reply():
	if flask.session['logged_in'] == 'true':
		conn = sqlite3.connect('message_board.db')
		curs = conn.cursor()
		edid = flask.request.args.get('editid')
		etext = flask.request.args.get('text')
		timestamp = time.time()

		curs.execute('SELECT author, text FROM messages WHERE id = ?', (edid,))
		res = curs.fetchone()
		authorid = res[0]
		orig_text = res[1]
		curs.execute('SELECT id FROM users WHERE username = ?', (flask.session['username'],))
		userid = curs.fetchone()[0]
		if authorid == userid:
			curs.execute('UPDATE messages SET text = ?, timestamp = ? WHERE id = ?', (etext, timestamp, edid))
			conn.commit()
			print('User {} edited post {}'.format(flask.session['username'], edid))
		else:
			flask.flash('You are not the author of this post')
			print('User {} attempted to edit post {} but does not have permission'.format(flask.session['username'], edid))
		conn.close()
	else:
		flask.flash('You are not logged in')
	return ('', 204)

@APP.route('/logout', methods=['POST'])
def logout():
	username = flask.session.pop('username', '')
	_ = flask.session.pop('logged_in', '')
	print('User {} logged out'.format(username))
	return flask.make_response(flask.redirect('/'))

def get_messages():
	conn = sqlite3.connect('message_board.db')
	conn.row_factory = sqlite3.Row
	curs = conn.cursor()

	curs.execute('SELECT messages.id as id, parent, users.username as author, text, timestamp FROM messages INNER JOIN users ON messages.author = users.id ORDER BY timestamp DESC')
	result = curs.fetchall()
	conn.close()
	messages = []
	if result != []:
		messages = [{'id':r['id'],
					 'parent':r['parent'],
					 'author':r['author'],
					 'text':r['text'].replace('\n', '<br>'),
					 'timestamp':time.strftime('%Y-%m-%d at %H:%M:%S', time.localtime(r['timestamp']))}
					 for r in result]
	return messages

if __name__ == '__main__':
	APP.run(debug=True)