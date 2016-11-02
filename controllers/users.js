var async = require( 'async' );

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
}
