var _ = require( 'lodash' );

module.exports = function( app, pwhash ) {
  var knex = require( 'knex' )( app.config );

  var lib = {};

  // Utility for turning a joined table into a hierarchy of objects
  lib.joinMerge = function( rows, primary_table_name ) {
    var result = [];
    rows.forEach( function( row ) {
      var primary_table = row[ primary_table_name ];
      var found = _.find( result, function( item ) { return item.id == primary_table.id; } );
      if ( found ) primary_table = found;
      else result.push( primary_table );
      _.forIn( row, function( sub_table, sub_table_name ) {
	if ( sub_table_name == primary_table_name ) return;
	if ( ! primary_table[ sub_table_name ] ) {
          primary_table[ sub_table_name ] = [];
          if ( sub_table.id !== null )
            primary_table[ sub_table_name ].push( sub_table );
	}
	else {
          if ( sub_table.id === null ) return;
          var found = _.find( primary_table[ sub_table_name ], function( item ) {
            return item.id == sub_table.id;
          });
          if ( ! found ) primary_table[ sub_table_name ].push( sub_table );
	}
      });
    });
    return result;
  };

  // Return a user based on id.  User must be ENABLED.
  lib.findUserById = function( id, cb ) {
    knex( 'users' )
    .select( 'users.*', 'roles.*' )
    .options({ nestTables: true })
    .leftJoin( 'users_roles', 'users_roles.user_id', '=', 'users.id' )
    .leftJoin( 'roles', 'roles.id', '=', 'users_roles.role_id' )
    .where({ 'users.id': id, 'users.status': 'ENABLED' })
    .then( function( rs ) {
      if ( ! rs.length ) return cb();
      var users = lib.joinMerge( rs, 'users' );
      return cb( null, users[0] );
    }).catch( cb );
  };

  // Return a user based on email or username.  User must be ENABLED.
  lib.findUserByName = function( username, cb ) {
    knex( 'users' )
    .select( 'users.*', 'roles.*' )
    .options({ nestTables: true })
    .leftJoin( 'users_roles', 'users_roles.user_id', '=', 'users.id' )
    .leftJoin( 'roles', 'roles.id', '=', 'users_roles.role_id' )
    .where({'users.status': 'ENABLED'}).andWhere( function() {
      this.where({ 'users.email': username }).orWhere({'users.username': username });
    })
    .then( function( rs ) {
      if ( ! rs.length ) return cb();
      var users = lib.joinMerge( rs, 'users' );
      return cb( null, users[0] );
    }).catch( cb );
  };

  // Save a user.  If password is included, it must already be hashed.
  lib.saveUser = function( user, cb ) {
    if ( user.password != undefined ) user.password_updated_on = Math.round( new Date().getTime() / 1000 );
    knex( 'users' ).where({ id: user.id }).update( user ).then( function() {
      return cb();
    }).catch( cb );
  };

  // Find users based on a simple query, ie. { email: address }
  lib.searchForUsers = function( query, cb ) {
    knex( 'users' ).where( query ).then( function( rs ) {
      cb( null, rs );
    }).catch( cb );
  };

  // Find users based on a search string.  See below.
  lib.searchForUsersQ = function( q, cb ) {
    var Q = '%'+q+'%';
    knex( 'users' )
    .where( 'givenName', 'like', Q )
    .orWhere( 'middleName', 'like', Q )
    .orWhere( 'surname', 'like', Q )
    .orWhere( 'username', 'like', Q )
    .orWhere( 'email', 'like', Q )
    .then( function( rs ) {
      cb( null, rs );
    }).catch( cb );
  };

  // Given a token, find the user with that token.
  lib.verifyPasswordResetToken = function( sptoken, cb ) {
    knex( 'users' ).where({ emailVerificationToken: sptoken }).then( function( rs ) {
      if ( ! rs.length ) return cb();
      else return cb( null, rs[0] );
    }).catch( cb );
  };

  // Given a user struct, find it and return it or create it if its not already in the db.
  lib.findOrCreateUser = function( user, password, cb ) {
    knex( 'users' ).where({ email: user.email }).then( function( rs ) {
      if ( rs.length ) return cb( null, rs[0] );
      pwhash( password, function( err, hash ) {
	if ( err ) return cb( err );
	user.password = hash;
	user.password_updated_on = Math.round( new Date().getTime() / 1000 );
	user.id = require( 'shortid' ).generate();
	if ( ! user.username ) user.username = user.email;
	if ( ! user.fullName ) {
          if ( ! user.middleName ) user.fullName = [ user.givenName, user.surname ].join( ' ' );
          else user.fullName = [ user.givenName, user.middleName, user.surname ].join( ' ' );
	}
	if ( ! user.status ) user.status = 'PENDING';
	if ( user.customData ) user.customData = JSON.stringify( user.customData );
	knex( 'users' ).insert( user ).then( function() {
          cb( null, user );
	}).catch( cb );
      });
    }).catch( cb );
  };

  // Given a role, find it and return it, or create it if its not already in the db
  lib.findOrCreateRole = function( role, cb ) {
    knex( 'roles' ).where({ name: role.name }).then( function( rs ) {
      if ( rs.length ) return cb( null, rs[0] );
      role.id = require( 'shortid' ).generate();
      knex( 'roles' ).insert( role ).then( function() {
	cb( null, role );
      }).catch( cb );
    }).catch( cb );
  };

  // Add a role to a user.  If the user already has it, nothing happens.  The role
  // must already exist.
  lib.addRoleToUser = function( role, user, cb ) {
    knex( 'users_roles' ).where({ user_id: user.id, role_id: role.id }).then( function( rs ) {
      if ( rs.length ) return cb();
      knex( 'users_roles' ).insert({ user_id: user.id, role_id: role.id }).then( function() {
	return cb();
      }).catch( cb );
    }).catch( cb );
  };

  lib.rememberPassword = function( user, cb ) {
    knex( 'old_passwords' ).insert({ user_id: user.id, password: user.password }).then( function() {
      cb();
    }).catch( cb );
  };

  lib.getOldPasswords = function( user, nMostRecent, cb ) {
    knex( 'old_passwords' ).where({ user_id: user.id }).orderBy( 'created_date', 'desc' ).limit( nMostRecent ).then( function( rs ) {
      cb( null, rs.map( function( u ) { return u.password; } ) );
    }).catch( cb );
  };

  return lib;
};

  
