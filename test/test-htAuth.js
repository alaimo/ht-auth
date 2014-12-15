var expect = require('expect.js'),
	fs = require('fs'),
	bcrypt = require('bcryptjs'),

	file = __dirname + '/.htpasswd',
	numUsers = 5,

	HtAuth = require('../HtAuth'),
	htAuth = HtAuth.create({file: file});

function generateFileData(numUsers) {
	var username = 'admin',
		password = 'pass123',
		users = HtAuth.line({username: username, password: password});

	for(var i = 1; i < numUsers; ++i){
		users += '\n' +
			HtAuth.line({username: username + i, password: password});
	}

	return users;
}

describe('HtAuth', function() {

	describe('#create', function() {
		it('should return a HtAuth instance', function() {
			expect(HtAuth()).to.be.a(HtAuth);
			expect(HtAuth.create()).to.be.a(HtAuth);
		});
	});

	describe('#hash', function() {
		it('should generate a valid bcrypt hash', function() {
			var password = 'pass123',
				hash = HtAuth.hash({password: password});

			expect(bcrypt.compareSync(password, hash)).to.be.ok();
		});

		it('should fail with invalid options', function() {
			expect(HtAuth.hash).to.throwException();
			expect(HtAuth.hash).
				withArgs({password: 'pass123', method: 'bob'}).
				to.throwException();
		});
	});

	describe('#verify', function() {
		it('should verify a bcrypt hash', function() {
			expect(HtAuth.verify({
				password: 'pass123',
				hash: HtAuth.hash({password: 'pass123'})
			})).
			to.be(true);
		});
	});

	describe('#line', function() {
		it('should return a valid htpasswd line', function() {
			var opts = {username: 'bob', password: 'pass123'},
				line = HtAuth.line(opts),
				user;

			expect(line).to.not.be.empty();

			user = line.split(':');
			expect(user.length).to.be(2);
			expect(user[0]).to.equal(opts.username);
			expect(user[1]).to.not.equal(opts.password);
			expect(bcrypt.compareSync(opts.password, user[1])).to.be(true);
		});
	});
}); // HtAuth

describe('htAuth', function() {

	after(function() {
		fs.unlinkSync(file);
	});

	describe('.find', function() {
		before(function() {
			fs.writeFileSync(file, generateFileData(numUsers), 'utf-8');
		});

		it('should find a user with a promise', function(done) {
			htAuth.find('admin').
				then(function(result) {
					expect(result).to.be.ok();
					expect(result.username).to.be('admin');
					return htAuth.find('admin2');
				}).
				then(function(result) {
					expect(result).to.be.ok();
					expect(result.username).to.be('admin2');
					return htAuth.find('admin4');
				}).
				then(function(result) {
					expect(result).to.be.ok();
					expect(result.username).to.be('admin4');
					expect(bcrypt.compareSync('pass123', result.password)).
						to.be.ok();
					done();
				}).
				catch(done);
		});

		it('should find a user with a callback', function(done) {
			htAuth.find('admin', function(err, user) {
				expect(err).to.not.be.ok();
				expect(user).to.be.ok();
				expect(user.username).to.be('admin');
				expect(bcrypt.compareSync('pass123', user.password)).
					to.be(true);
				done();
			});
		});
	}); // .find

	describe('.findAll', function() {
		before(function() {
			fs.writeFileSync(file, generateFileData(numUsers), 'utf-8');
		});

		it('should return a all user lines via promise', function(done) {
			htAuth.findAll().
				then(function(results) {
					expect(results).to.be.an(Array);
					expect(results.length).to.be(numUsers);
					done();
				}).
				catch(done);
		});

		it('should return a all user lines via callback', function(done) {
			htAuth.findAll(function(err, users) {
				expect(err).to.not.be.ok();
				expect(users).to.be.an(Array);
				expect(users.length).to.be(numUsers);
				done();
			});
		});

		it('should return user objects via promise', function(done) {
			htAuth.findAll({parse: true}).
				then(function(results) {
					expect(results).to.be.an(Array);
					expect(results.length).to.be(numUsers);
					expect(results[0].username).to.be('admin');
					expect(bcrypt.compareSync('pass123', results[0].password)).
						to.be(true);
					done();
				}).
				catch(done);
		});

		it('should return user objects via callback', function(done) {
			htAuth.findAll({parse: true}, function(err, users) {
				expect(err).to.not.be.ok();
				expect(users).to.be.an(Array);
				expect(users.length).to.be(numUsers);
				expect(users[0].username).to.be('admin');
				expect(bcrypt.compareSync('pass123', users[0].password)).
					to.be(true);
				done();
			});
		});

		it('should return [] when there are no users', function(done) {
			var htAuth = HtAuth.create({file: __dirname + '/.nofile'});
			htAuth.findAll().
				then(function(result) {
					expect(result).to.be.an(Array);
					expect(result).to.be.empty();
					done();
				});
		});
	}); // .findAll

	describe('.add', function() {
		beforeEach(function() {
			fs.writeFileSync(file, generateFileData(numUsers), 'utf-8');
		});

		it('should add a new user via promise', function(done) {
			htAuth.add({username: 'bob', password: 'pass123'}).
				then(function() {
					return htAuth.find('bob');
				}).
				then(function(result) {
					expect(result).to.be.ok();
					expect(result.username).to.be('bob');
					expect(bcrypt.compareSync('pass123', result.password)).
						to.be(true);
					done();
				}).
				catch(done);
		});

		it('should add a new user via callback', function(done) {
			htAuth.add({username: 'bob', password: 'pass123'}, function(err) {
				expect(err).to.not.be.ok();
				htAuth.find('bob', function(err, user) {
					expect(err).to.not.be.ok();
					expect(user).to.be.ok();
					expect(user.username).to.be('bob');
					expect(bcrypt.compareSync('pass123', user.password)).
						to.be(true);
					done();
				});
			});
		});

		it('should fail is a user exists', function(done) {
			htAuth.add({username: 'admin', password: 'pass123'}).
				then(function(result) {
					expect().fail();
				}).
				catch(function(err) {
					expect(err).be.ok();
					expect(err.message).to.be('User already exists');
					done();
				});
		});

		it('should overwrite a user if forced', function(done) {
			htAuth.add({username: 'admin', password: 'pass1234', force: true}).
				then(function() {
					return htAuth.find('admin');
				}).
				then(function(result) {
					expect(bcrypt.compareSync('pass1234', result.password)).
						to.be(true);
					done();
				}).
				catch(done);
		});

		describe('::no file', function() {
			var file = __dirname + '/.nofile';

			after(function() {
				fs.unlinkSync(file);
			});

			it('should succeed if no file exists', function(done) {
				var htAuth = HtAuth.create({file: file});
				htAuth.add({username: 'bob', password: 'pass123'}).
					then(function() {
						return htAuth.findAll({parse: true});
					}).
					then(function(result) {
						expect(result).to.be.an(Array);
						expect(result.length).to.be(1);
						expect(result[0].username).to.be('bob');
						done();
					}).
					catch(done);
			});
		});
	}); // .add

	describe('.remove', function() {
		beforeEach(function() {
			fs.writeFileSync(file, generateFileData(numUsers), 'utf-8');
		});

		it('should remove a user via promise', function(done) {
			htAuth.remove({username: 'admin'}).
				then(function() {
					return htAuth.find('admin');
				}).
				then(function(user) {
					expect(user).to.be(null);
					done();
				}).
				catch(done);
		});

		it('should remove a user via callback', function(done) {
			htAuth.remove({username: 'admin'}, function(err) {
				expect(err).to.be(null);
				htAuth.find('admin', function(err, user) {
					expect(err).to.be(null);
					expect(user).to.be(null);
					done();
				});
			});
		});

		it('should not fail when the user is not found', function(done) {
			htAuth.remove({username: 'bob'}, done);
		});

		it('should not fail when the file is not found', function(done) {
			var htAuth = HtAuth.create({file: 'nofile'});
			htAuth.remove({username: 'bob'}, done);
		});
	}); // .remove

	describe('.changePassword', function() {
		beforeEach(function() {
			fs.writeFileSync(file, generateFileData(numUsers), 'utf-8');
		});

		it('should change a password via promise', function(done) {
			htAuth.changePassword({
				username: 'admin',
				password: 'pass1234',
				currentPassword: 'pass123'
			}).
			then(function() {
				return htAuth.find('admin');
			}).
			then(function(user) {
				expect(bcrypt.compareSync('pass1234', user.password)).
					to.be(true);
				done();
			}).
			catch(done);
		});

		it('should change a password via callback', function(done) {
			htAuth.changePassword({
					username: 'admin',
					password: 'pass1234',
					currentPassword: 'pass123'
				},
				function(err) {
					expect(err).to.be(null);
					htAuth.find('admin', function(err, user) {
						expect(bcrypt.compareSync('pass1234', user.password)).
							to.be(true);
						done();
					});
				}
			);
		});

		it('should fail on bad credentials', function(done) {
			htAuth.changePassword({
				username: 'admin',
				password: 'pass1234',
				currentPassword: 'wrong'
			}).
			then(function() {
				expect().fail();
			}).
			catch(function(err) {
				expect(err.message).to.be('Invalid credentials');
				done();
			});
		});

		it('should change a password if forced', function(done) {
			htAuth.changePassword({
				username: 'admin',
				password: 'pass1234',
				currentPassword: 'wrong',
				force: true
			}).
			then(function() {
				return htAuth.find('admin');
			}).
			then(function(user) {
				expect(bcrypt.compareSync('pass1234', user.password)).
					to.be(true);
				done();
			}).
			catch(done);
		});

		it('should fail when the user does not exist', function(done) {
			htAuth.changePassword({
				username: 'doesnotexist',
				password: 'pass1234',
				currentPassword: 'pass123'
			}).
			then(function() {
				expect().fail();
			}).
			catch(function(err) {
				expect(err.message).to.be('User does not exist');
				done();
			});
		});

		it('should fail when the file does not exist', function(done) {
			var htAuth = HtAuth.create({file: 'nofile'});
			htAuth.changePassword({
				username: 'doesnotexist',
				password: 'pass1234',
				currentPassword: 'pass123'
			}).
			then(function() {
				expect().fail();
			}).
			catch(function(err) {
				expect(err.message).to.be('User does not exist');
				done();
			});
		});
	}); // .change password

}); // htAuth