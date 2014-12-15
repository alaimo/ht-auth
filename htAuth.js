var BluebirdPromise = require('bluebird'),
	fs = BluebirdPromise.promisifyAll(require('fs')),
	bcrypt = require('bcryptjs'),

	defaultOpts = {
		file: __dirname + '/.htpasswd'
	};

/**
 * Constructor
 * @param opts {Object}
 *		opts = {file: <path to a htpasswd file}
 */
function HtAuth (opts) {
	if(!(this instanceof HtAuth)) {
		return HtAuth.create(opts);
	}

	opts = opts || defaultOpts;
	this.file = opts.file || defaultOpts.file;
}

// -----------------------------------------------------------------------------
// Private Methods
// -----------------------------------------------------------------------------

/**
 * Finds the index of username in an Array of htpasswd lines
 * @param username {String}
 * @param list {Array}
 */
function findUserInList(username, list) {
	var len;
	if(list) {
		len = list.length;
		while(len-- && list[len].split(':')[0] !== username) {
			// empty
		}
		return len;
	}
	return -1;
}

/**
 * Predicate for "file not found" OperationalErrors
 * @param err {Error}
 */
function fileNotFound(err) {
	return (err instanceof BluebirdPromise.OperationalError) &&
		 err.cause.code === 'ENOENT';
}

// -----------------------------------------------------------------------------
// Class Constants
// -----------------------------------------------------------------------------

HtAuth.BCRYPT = 'BCRYPT';

// -----------------------------------------------------------------------------
// Class Methods
// -----------------------------------------------------------------------------

/**
 * Factory Method to create a HtAuth instance
 * @param opts {Object}
 */
HtAuth.create = function(opts) {
	return new HtAuth(opts);
};

/**
 * Generates a string hash for opts.password using opts.method
 * @param opts {Object}
 */
HtAuth.hash = function(opts) {
	var method;
	if(!opts || !opts.password) {
		throw new Error('Invalid input');
	}

	// default to bcrypt hashing
	method = opts.method || HtAuth.BCRYPT;
	switch(method) {
		case HtAuth.BCRYPT:
			return bcrypt.hashSync(opts.password);
		default:
			throw new Error('Unsupported method');
	}
};

/**
 * Validates opts.password against opts.hash using opts.method
 * @param opts {Object}
 */
HtAuth.verify = function(opts) {
	if(!opts || !opts.password || !opts.hash) {
		throw new Error('Invalid input');
	}

	// default to bcrypt hashing
	method = opts.method || HtAuth.BCRYPT;
	switch(method) {
		case HtAuth.BCRYPT:
			return bcrypt.compareSync(opts.password, opts.hash);
		default:
			throw new Error('Unsupported method');
	}
};

/**
 * Generates a htpasswd line. e.g. username:hash
 * @param opts {Object}
 */
HtAuth.line = function(opts) {
	if(!opts || !opts.username) {
		throw new Error('Invalid input');
	}
	return opts.username + ':' + HtAuth.hash(opts);
};

// -----------------------------------------------------------------------------
// Instance Methods
// -----------------------------------------------------------------------------

/**
 * Finds a line for username and responds with {username, password}.
 * Password will be the hash from the htpasswd file
 * @param opts {Object}
 * @param callback {Function} (optional)
 */
HtAuth.prototype.find = function(username, callback) {
	return fs.readFileAsync(this.file, 'utf-8').
		then(function(data) {
			var lines = data.split('\n'),
				userIndex = findUserInList(username, lines),
				user = null;

			if(userIndex !== -1) {
				user = lines[userIndex].split(':');
				user = {username: user[0], password: user[1]};
			}

			if(callback) {
				callback(null, user);
			}
			return BluebirdPromise.resolve(user);
		}).
		catch(fileNotFound, function(err) {
			// gracefully handle file not found errors
			if(callback) {
				callback(null, null);
			}
			return BluebirdPromise.resolve(null);
		}).
		catch(function(err) {
			if(callback) {
				callback(err);
			}
			return BluebirdPromise.reject(err);
		});
};

/**
 * Return an array of raw or parsed lines from the htpasswd file. Pass
 * opts.parse = true to get User Objects instead of Strings
 * @param opts {Object}
 * @param callback {Function} (optional)
 */
HtAuth.prototype.findAll = function(opts, callback) {
	// allow for opts to be optional
	if(opts instanceof Function) {
		callback = opts;
		opts = null;
	}

	return fs.readFileAsync(this.file, 'utf-8').
		then(function(data) {
			var users = data.split('\n');

			if(opts && opts.parse) {
				users = users.map(function(val) {
					var user = val.split(':');
					return {username: user[0], password: user[1]};
				});
			}

			if(callback) {
				callback(null, users);
			}
			return BluebirdPromise.resolve(users);
		}).
		catch(fileNotFound, function(err) {
			// gracefully handle file not found errors
			if(callback) {
				callback(null, []);
			}
			return BluebirdPromise.resolve([]);
		}).
		catch(function(err) {
			if(callback) {
				callback(err);
			}
			return BluebirdPromise.reject(err);
		});
};

/**
 * Adds a user line to the htpasswd file. Fails if a username already exists.
 * Set opts.force = true to overwrite a user. Creates a new file if needed.
 * @param opts {Object}
 * @param callback {Function} (optional)
 */
HtAuth.prototype.add = function(opts, callback) {
	var self = this;
	return this.findAll().
		then(function(users) {
			var userIndex = findUserInList(opts.username, users);
			if(userIndex === -1) {
				users.push(HtAuth.line(opts));
			} else if(opts.force) {
				users[userIndex] = HtAuth.line(opts);
			} else {
				return BluebirdPromise.reject(new Error('User already exists'));
			}
			return fs.writeFileAsync(self.file, users.join('\n'), 'utf-8');
		}).
		then(function() {
			if(callback) {
				callback(null);
			}
			return BluebirdPromise.resolve();
		}).
		catch(fileNotFound, function(err) {
			// gracefully handle file not found errors
			return fs.writeFileAsync(self.file, HtAuth.line(opts), 'utf-8').
				then(function() {
					if(callback) {
						callback(null);
					}
					return BluebirdPromise.resolve();
				});
		}).
		catch(function(err) {
			if(callback) {
				callback(err);
			}
			return BluebirdPromise.reject(err);
		});
};

/**
 * Removes a user from the file.  Returns successfully if the user or file does
 * not exist
 * @param opts {Object}
 * @param callback {Function} (optional)
 */
HtAuth.prototype.remove = function(opts, callback) {
	var self = this;
	return this.findAll().
		then(function(users) {
			var userIndex = findUserInList(opts.username, users);
			if(userIndex !== -1) {
				users.splice(userIndex, 1);
				return fs.writeFileAsync(self.file, users.join('\n'), 'utf-8');
			}
			return BluebirdPromise.resolve(true);
		}).
		then(function() {
			if(callback) {
				callback(null);
			}
			return BluebirdPromise.resolve();
		}).
		catch(fileNotFound, function() {
			// gracefully handle file not found errors
			if(callback) {
				callback(null);
			}
			return BluebirdPromise.resolve();
		}).
		catch(function(err) {
			if(callback) {
				callback(err);
			}
			return BluebirdPromise.reject(err);
		});
};

/**
 * Changes the password for a user.  Fails if the user or file does not exist.
 * Fails if opt.currentPassword is incorrect.  Set opts.force = true to
 * overwrite the existing password without verification.
 * @param opts {Object}
 * @param callback {Function} (optional)
 */
HtAuth.prototype.changePassword = function(opts, callback) {
	var self = this;
	return this.findAll().
		then(function(users) {
			var userIndex = findUserInList(opts.username, users),
				user;

			if(userIndex === -1) {
				return BluebirdPromise.reject(new Error('User does not exist'));
			}

			if(!opts.force && !HtAuth.verify({
					password: opts.currentPassword,
					hash: users[userIndex].split(':')[1]
				})) {
				return BluebirdPromise.reject(new Error('Invalid credentials'));
			}

			users[userIndex] = HtAuth.line(opts);
			return fs.writeFileAsync(self.file, users.join('\n'), 'utf-8');
		}).
		then(function() {
			if(callback) {
				callback(null);
			}
			return BluebirdPromise.resolve();
		}).
		catch(fileNotFound, function(err) {
			// It makes sense to convert the error here.
			return BluebirdPromise.reject(new Error('User does not exist'));
		}).
		catch(function(err) {
			if(callback) {
				callback(err);
			}
			return BluebirdPromise.reject(err);
		});
};

module.exports = HtAuth;
