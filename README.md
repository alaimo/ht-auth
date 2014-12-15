# ht-auth

Simple authentication with an htpasswd file for node js applications

* Supports Promises and Node-style callbacks
* Credentials are stored as bcrypt hashes
* Writen in JavaScript
* Tested with `mocha`
* `jshint` compliant
 
### What is an htpasswd file?
An htpasswd file is a way of storing user credentials in a text file.  Often used in conjuction with basic-auth. The file consists of one user per line in the following format:

`username:<password hash>`

### Installation

`TBD`

### Getting Started

``` js
var HtAuth = require('ht-auth'),
  htAuth = HtAuth.create({file: '/.htpasswd'});
```

### Add a user
``` js
// add user:<bcrypt hash> to the file with callback.
// this method will create the file if it does not exist.
htAuth.add({username: 'user', password: 'password'}, function(err) {
  ...
});

// promise to add a user
htAuth.add({username: 'user', password: 'password'}).
  then(function() { 
    ... 
  });
  
// add will fail if a user already exists, to overwrite
htAuth.add({username: 'user', password: 'password', force: true}).
  then(function{ 
    ... 
  });
```

### Find users
``` js
// callback
htAuth.find('user', function(err, user) {
  // user will be null if it is not in the file
  if(user) {
    console.log('username: ', user.username);
  }
});

// promise
htAuth.find('user').
  then(function(user) { 
    ... 
  }).
  catch(function(err) { 
    ... 
  });

// all user lines
htAuth.findAll().
  then(function(lines) {
    // returns unparsed user lines
    // returns [] if file is empty or does not exist
  });

// all users as {username, password}.
htAuth.findAll({parse: true}).
  then(function(users) {
    // returns [] if file is empty or does not exist
    console.log(users[0].username);
  });
```

### Validate a user
``` js
htAuth.find('user').
  then(function(user) {
    if(user && 
      HtAuth.verify({password: 'password', currentPassword: user.password}) {
      ...
    } else {
      ...
    }
  });
```

### Change a password
``` js
var opts = {
	username: 'user',
	password: 'new password',
	currentPassword: 'password'
};

// validates the current password first, add opts.force = true
// to ignore validation
htAuth.changePassword(opts).
  then(function() {
    ...
  }).
  catch(function(err) {
    if(err) {
      if(err === 'Invalid credentials') {
        ...
      } 
      ...
    }
  });
```

### Remove a user
```
// callback
htAuth.remove({username: 'admin'}, function(err) {
	 ...
});

// promise
htAuth.remove({username: 'admin'}).
  then(function() {
	  ...
  }).
  catch(function(err) {
    ...
  });
```

## Tests

Tests are implemented with `mocha` and `expect.js`.  `npm test` requires `grunt` and `grunt-cli`.

## License

The MIT License (MIT)

Copyright (c) 2014 Jonathan Alaimo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
