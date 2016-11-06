var async = require( 'async' );
var _ = require( 'lodash' );

module.exports = function( app, udb ) {

  function names( user ) {
    if ( ! user.fullName && ( user.givenName && user.surname ) ) {
      if ( user.middleName )
	user.fullName = [ user.givenName, user.middleName, user.surname ].join( ' ' );
      else
	user.fullName = [ user.givenName, user.surname ].join( ' ' );
    }
    else if ( user.fullName && ! ( user.givenName && user.surname ) ) {
      var parts = user.fullName.split( /\s+/ );
      user.givenName = parts.shift();
      user.surname = parts.join( ' ' );
    }
  }

  app.post( '/users/list', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {

    var accountId = req.body.accountId;

    // If the accountId is undefined, then calling user must be super-admin
    // If the accountId is defined, then user must be either super-admin, or the user's accountId must match the
    // incoming accountId.

    if ( accountId == undefined ) {
      if ( ! req.user.has( 'super-admin' ) ) {
	accountId = req.user.accounts[0].id; // force it to the accountId of the calling user
      }
    }
    else if ( ! req.user.has( 'super-admin' ) && ( accountId != req.user.accounts[0].id ) ) {
      return res.status( 403 ).send( 'Calling user does not belong to the account being asked for.' );
    }

    var where = {};
    if ( accountId != undefined ) where[ 'users.account_id' ] = accountId;

    udb.searchForUsers( where, req.body, function( err, data ) {
      if ( err ) return next( err );
      res.jsonp( data );
    });
    
  });
  
  app.post( '/users/remove', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var userId = req.body.userId;

    if ( req.user.has( 'super-admin' ) ) {
      udb.removeUser( userId, function( err ) {
	if ( err ) return next( err );
	res.jsonp();
      });
    }
    else {
      udb.findAnyUserById( userId, function( err, user ) {
	if ( err ) return next( err );
	var userAccountId = user.accounts[0].id;
	if ( req.user.accounts[0].id == userAccountId ) {
	  udb.removeUser( userId, function( err ) {
	    if ( err ) return next( err );
	    res.jsonp();
	  });
	}
	else {
	  next( new Error( 'logged in user does not have permission to remove user id: ' + userId ) );
	}
      });
    }
  });
  
  app.post( '/users/update', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var user = req.body;

    names( user );
    
    if ( user.id ) {
      udb.findAnyUserById( user.id, function( err, dbuser ) {
	if ( err ) return next( err );
	if ( ! dbuser ) return next( new Error( 'user not found' ) );
	if ( ( dbuser.account_id != req.user.accounts[0].id ) && ! req.user.has( 'super-admin' ) ) {
	  return next( new Error( 'only super-admin can edit a user on a different account.' ) );
	}
	var changes = {};
	[ 'id', 'givenName', 'middleName', 'surname', 'email', 'status', 'customData', 'fullName' ].forEach( function( f ) {
	  changes[f] = user[f];
	});
	// We will need to remove all roles from this user and then add the roles coming in.
	async.series([
	  function( cb ) {
	    async.each( dbuser.roles, function( role, cb ) {
	      udb.removeRoleFromUser( role, dbuser, cb );
	    }, cb );
	  },
	  function( cb ) {
	    async.each( user.roles, function( role, cb ) {
	      role.account_id = dbuser.account_id;
	      udb.findOrCreateRole( role, function( err, role ) {
		if ( err ) return cb( err );
		udb.addRoleToUser( role, dbuser, cb );
	      });
	    }, cb );
	  },
	  function( cb ) {
	    udb.saveUser( changes, cb );
	  },
	], function( err ) {
	  udb.findAnyUserById( user.id, function( err, dbuser ) {
	    if ( err ) return next( err );
	    res.jsonp( dbuser );
	  });
	});
      });
    }
    else {
      // If status is not set, then its PENDING
      //
      // This is a new user.  If status!=PENDING, then there better be a password field.  Otherwise the account verification
      // flow will establish a password for this user.
      //
      if ( user.status == undefined ) user.status = 'PENDING';
      if ( user.status != 'PENDING' && ! ( user.password && user.password.length ) ) {
	return next( new Error( 'New user: if status is not PENDING, then a password field is required.' ) );
      }
      if ( user.status == 'PENDING' ) {
	user.password = udb.generateRandomPassword();
      }
      [ 'givenName', 'surname', 'email', 'fullName' ].forEach( function( f ) {
	if ( user[f] == undefined ) {
	  return next( new Error( 'New user: required field is missing: ' + f ) );
	}
      });
      if ( ! user.account_id ) user.account_id = req.user.accounts[0].id;
      if ( ( user.account_id != req.user.accounts[0].id ) && ! req.user.has( 'super-admin' ) ) {
	return next( new Error( 'New user: only a super-admin can add a user to different account.' ) );
      }
      var userRoles = user.roles;
      delete user.roles;
      async.waterfall([
	function( cb ) {
	  udb.searchForUsers({ email: user.email }, function( err, users ) {
	    if ( err ) return cb( err );
	    if ( users && users.length ) return cb( new Error( 'A user with that email already exists.' ) );
	    cb();
	  });
	},
	function( cb ) {
	  udb.findOrCreateUser( user, user.password || udb.generateRandomPassword(), cb );
	},
	function( user, cb ) {
	  async.eachSeries( userRoles || [], function( role, cb ) {
	    udb.addRoleToUser( role, user, cb );
	  }, function( err ) {
	    cb( err, user );
	  });
	},
	function( user, cb ) {
	  if ( user.status != 'PENDING' ) return cb( null, user );
	  udb.newUserWorkflow( user, function( err ) {
	    cb( err, user );
	  });
	}
      ], function( err, user ) {
	if ( err ) return next( err );
	udb.findAnyUserById( user.id, function( err, dbuser ) {
	  if ( err ) return next( err );
	  res.jsonp( dbuser );
	});
      });
    }
  });

  app.post( '/users/check_password', function( req, res, next ) {
    var error = udb.checkPassword( req.body.password );
    res.jsonp({
      good: ( error ? false : true ),
      error: error
    });
  });

  app.post( '/users/change_account_status', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var userId = req.body.userId;
    var newStatus = req.body.newStatus;
    
    udb.findAnyUserById( userId, function( err, user ) {
      if ( err ) return next( err );
      if ( ! req.user.has( 'super-admin' ) ) {
	if ( req.user.accounts[0].id != user.accountId ) {
	  return res.status( 403 ).send( 'Logged in user does not have permission to perform this action.' );
	}
      }

      var u = {
	id: userId,
	status: newStatus,
      };
      if ( newStatus == 'ENABLED' ) {
	u.last_failed_login_on = 0;
	u.failed_login_count = 0;
      }

      udb.saveUser(u, function( err ) {
	if ( err ) return next( err );
	user.status = newStatus;
	res.jsonp( user );
      });
      
    });
  });

  app.post( '/users/reset_password', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var userId = req.body.userId;
    udb.findAnyUserById( userId, function( err, user ) {
      if ( err ) return next( err );
      if ( ! req.user.has( 'super-admin' ) ) {
	if ( req.user.accounts[0].id != user.accountId ) {
	  return res.status( 403 ).send( 'Logged in user does not have permission to perform this action.' );
	}
      }

      udb.resetPassword( user, function( err ) {
	if ( err ) return next( err );
	res.jsonp({});
      });
      
    });
  });

  app.post( '/users/resend_invite', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var userId = req.body.userId;
    udb.findAnyUserById( userId, function( err, user ) {
      if ( err ) return next( err );
      if ( ! req.user.has( 'super-admin' ) ) {
	if ( req.user.accounts[0].id != user.accountId ) {
	  return res.status( 403 ).send( 'Logged in user does not have permission to perform this action.' );
	}
      }

      udb.newUserWorkflow( user, function( err ) {
	if ( err ) return next( err );
	res.jsonp({});
      });
      
    });
  });

  // curl -v  -F 'file=@data/users.xlsx;type=application/xlsx' http://192.168.99.104/users/import
  app.post( '/users/import', udb.authenticated, udb.authorized( ['super-admin', 'admin'], false ), function( req, res, next ) {
    var streamer = require( '../lib/stream-csv' )(app);
    var multiparty = require( 'multiparty' );
    var fs = require( 'fs' );
    var form = new multiparty.Form({
      autoFiles: true,
      maxFilesSize: 26214400, // 25 Mb
    });

    function clean( str ) {
      if ( ! str ) return null;
      var c = str.replace( /^\s+/, '' ).replace( /\s+$/, '' );
      if ( c == '' ) return null;
      else return c;
    }

    function isValid( u, headers ) {
      for( var i=0; i<headers.length; i++ ) {
	u[ headers[i] ] = clean( u[ headers[i] ] );
	if ( headers[i] != 'role' && u[ headers[i] ] == undefined ) {
	  return new Error( 'Missing value for: ' + headers[i] );
	}
      }
      var re = /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\".+\"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
      if ( ! re.test( u.email ) )
	return new Error( 'Email field does not appear to be valid: ' + u.email );
      return null;
    }

    function addUser( u, options, cb ) {
      var dbu = {
        email: u.email,
        givenName: u.givenname,
        surname: u.surname,
        customData: {},
        status: ( options.disableWorkflow ? 'ENABLED' : 'PENDING' )
      };
      if ( ! options.isSuperAdmin ) u.account = options.accountName;
      async.waterfall([
        function( cb ) {
	  //app.log.debug( 'add account:', u.account );
          udb.findOrCreateAccount({ name: u.account }, function( err, account ) {
            if ( err ) return cb( err );
            dbu.account_id = account.id;
            cb( null, account );
          });
        },
        function( account, cb ) {
          // every account should have an admin role
	  //app.log.debug( 'add admin to ', account.name, account.id );
          udb.findOrCreateRole( { name: 'admin', account_id: account.id }, function( err, role ) {
            if ( err ) return cb( err );
            cb( null, account );
          });
        },
        function( account, cb ) {
	  if ( ! u.role ) return cb( null, null );
	  //app.log.debug( 'add role', u.role, 'to', account.name, account.id );
          udb.findOrCreateRole( { name: u.role, account_id: account.id }, function( err, role ) {
            if ( err ) return cb( err );
            cb( null, role );
          });
        },
        function( role, cb ) {
	  //app.log.debug( 'add user:', dbu );
          udb.findOrCreateUser( dbu, (u.password || 'new123'), function( err, user ) {
            if ( err ) return cb( err );
            cb( null, user, role );
          });
        },
        function( user, role, cb ) {
          if ( ! role ) return cb( null, user );
	  //app.log.debug( 'add role', role.name, 'to user', user.email );
          udb.addRoleToUser( role, user, function( err ) {
	    if ( err ) app.log.error( err );
            if ( err ) return cb( err );
            cb( null, user );
          });
        },
        function( user, cb ) {
          if ( options.disableWorkflow ) return cb( null, user );
	  // if there is already an email pending, don't resend
	  if ( (user.status == 'PENDING') && user.emailVerificationToken ) return cb( null, user );
	  //app.log.debug( 'sending workflow email to', user.email );
          udb.newUserWorkflow( user, function( err ) {
            if ( err ) return cb( err );
            cb( null, user );
          });
        },
      ], function( err, user ) {
        if ( err ) return cb( err );
        app.log.info( 'User Import:', user );
        return cb( null, user );
      });
    }
    
    form.parse(req, function( err, _fields, _files ) {
      if ( err ) return next( err );
      var fields = {};
      _.forIn( _fields, function( v, k ) {
	if ( Array.isArray( v ) ) v = v[0];
	fields[k] = v;
      });

      var ignoreHeaders = fields.ignoreHeaders; // a checkbox on the file upload form
      var disableNewUserWorkflow = fields.disableNewUserWorkflow;  // ditto
      
      var files = [];
      _.forIn( _files, function( v, k ) {
	files = _.concat( files, v );
      });
      if ( files.length != 1 ) {
	files.forEach( function( file ) {
	  require( 'fs' ).unlinkSync( file.path );
	});
	return res.status( 400 ).send( 'One file and one file only supported!' );
      }
      else {
	var headers = [
	  'givenname', 'surname', 'email', 'role', 'password',
	];

	// super-admins can import users into different accounts
	var isSuperAdmin = req.user.has( 'super-admin' );
	var loggedInUserAccountName = req.user.accounts[0].name;

	if ( isSuperAdmin ) headers.push( 'account' );
	
	// make sure we deal with rows sequencially!
	var rowNum = 0;
	var q = async.queue( function( o, cb ) {
	  if ( o == null ) {
	    if ( ! res.headersSent ) res.jsonp();  // on the EOF, send normal response
	    return process.nextTick( cb );
	  }
	  if ( rowNum == 0 && ignoreHeaders ) { rowNum += 1; return cb() };
	  //app.log.debug( o );

	  var problems = isValid( o, headers );
	  if ( problems ) return cb( problems );

	  addUser( o, { disableWorkflow: disableNewUserWorkflow, isSuperAdmin: isSuperAdmin, accountName: loggedInUserAccountName }, function( err, user ) {
	    if ( err ) return cb( err );
	    rowNum += 1;
	    cb();
	  });
	}, 1 );

	// When the queue is finished, delete the uploaded file if it still exists
	q.drain( function() {
	  if ( fs.existsSync( files[0].path ) ) 
	    fs.unlinkSync( files[0].path );
	});

	// When an error occurs, send it back to the client as fast as possible, but
	// because we're streaming the csv, we can't really stop.
	streamer.process( files[0].path, files[0].headers[ 'content-type' ], function( err, row ) {
	  if ( err ) {
	    if ( ! res.headersSent ) return res.status( 400 ).send( err.message );
	  }
	  else if ( row == null ) {
	    if ( fs.existsSync( files[0].path ) ) 
	      fs.unlinkSync( files[0].path );
	    q.push( null );
	  }
	  else {
	    var o = _.zipObject( headers, row );
	    q.push( o, function( err ) {
	      if ( err ) {
		if ( ! res.headersSent ) return res.status( 400 ).send( err.message );
	      }
	    });
	  }
	});
      }
    });
  });
}
