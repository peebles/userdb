var _ = require( 'lodash' );
module.exports = function( app ) {
  var config = app.config;
  return function( user ) {
    if ( user.status == undefined ) user.status = 'ENABLED';
    user.href = config.accounts_href + '/' + user.id;
    if ( user.customData ) user.customData = JSON.parse( user.customData );
    else user.customData = {};
    user.groups = {
      href: user.href + '/groups',
      items: _.map( user.roles, function( role ) {
	return {
          href: config.groups_href + '/' + role.id,
          description: role.description,
          name: role.name,
          status: role.status || 'ENABLED',
          customData: ( role.customData ? JSON.parse( role.customData ) : {} ),
	};
      }),
    };
    delete user.roles;

    // helper functions for the server side

    // user.has( 'admin' )
    // return true if the user has the role 'admin'
    //
    user[ 'has' ] = function( role ) {
      try {
	var g = _.find( this.groups.items, function( i ) { return i.name == role; } );
	if ( g ) return true;
	else return false;
      } catch( err ) {
	app.log.error( err );
	return false;
      }
    };

    // user.can( [ 'ops', 'admin' ], all );
    // returns true if the user has a role that matches one of the
    // input roles.  If all is present and true, then the user
    // must have all the roles specified.  If no arguments at
    // all are passed, this function always returns true.  If the
    // user has 'super_admin', this function returns true.
    //
    user[ 'can' ] = function( requiredRoles, all ) {
      all = all === undefined ? false : all;
      if ( requiredRoles === undefined ) return true;
      if ( this.has( 'super_admin' ) ) return true;
      var user_groups = _.map( this.groups.items, 'name' );
      var intersection = _.intersection( user_groups, requiredRoles );
      if ( ! intersection.length ) return false;
      if ( ! all && intersection.length ) return true;
      if ( intersection.length == requiredRoles.length ) return true;
      return false;
    };

    user[ 'canOnly' ] = function( requiredRoles, all ) {
      all = all === undefined ? false : all;
      if ( requiredRoles === undefined ) return true;
      // if ( this.has( 'super_admin' ) ) return true;
      var user_groups = _.map( this.groups.items, 'name' );
      var intersection = _.intersection( user_groups, requiredRoles );
      if ( ! intersection.length ) return false;
      if ( ! all && intersection.length ) return true;
      if ( intersection.length == requiredRoles.length ) return true;
      return false;
    };

    user.id = require( 'path' ).basename( user.href );

    var groups = user.groups;

    var accts = [];
    var roles = [];
    groups.items.forEach( function( g ) {
      if ( g.customData.account ) accts.push( g );
      else roles.push( g.name );
    });

    user._accounts = accts;
    user._roles = roles;

    user.accounts = function() {
      return user._accounts;
    }

    user.account = function() {
      return user._accounts[0];
    }

    user.roles = function() {
      return user._roles;
    }

    user.role = function() {
      return user._roles[0];
    }
    
    return user;
  }
};
